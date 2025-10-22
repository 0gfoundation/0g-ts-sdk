import { DEFAULT_SEGMENT_SIZE, DEFAULT_SEGMENT_MAX_CHUNKS, DEFAULT_CHUNK_SIZE, } from '../constant.js';
import { delay, getMarketContract, SegmentRange, txWithGasAdjustment, } from '../utils.js';
import { encodeBase64, ethers } from 'ethers';
import { calculatePrice, getShardConfigs } from './utils.js';
import { checkReplica } from '../common/index.js';
export class Uploader {
    nodes;
    provider;
    flow;
    gasPrice;
    gasLimit;
    constructor(nodes, providerRpc, flow, gasPrice = BigInt('0'), gasLimit = BigInt('0')) {
        this.nodes = nodes;
        this.provider = new ethers.JsonRpcProvider(providerRpc);
        this.flow = flow;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
    }
    async uploadFile(file, opts, retryOpts) {
        var [tree, err] = await file.merkleTree();
        if (err != null || tree == null || tree.rootHash() == null) {
            return [
                { txHash: '', rootHash: '' },
                new Error('Failed to create Merkle tree'),
            ];
        }
        const rootHash = tree.rootHash();
        console.log('Data prepared to upload', 'root=' + rootHash, 'size=' + file.size(), 'numSegments=' + file.numSegments(), 'numChunks=' + file.numChunks());
        let txSeq = null;
        let receipt = null;
        let info = await this.findExistingFileInfo(rootHash);
        if (!opts.skipTx || info === null) {
            var [submission, err] = await file.createSubmission(opts.tags);
            if (err !== null || submission === null) {
                return [
                    { txHash: '', rootHash },
                    new Error('Failed to create submission'),
                ];
            }
            const [txReceipt, txErr] = await this.submitTransaction(submission, opts, retryOpts);
            if (txErr !== null) {
                return [{ txHash: '', rootHash }, txErr];
            }
            receipt = txReceipt;
            console.log('Transaction hash:', receipt.hash);
            const txSeqs = await this.processLogs(receipt);
            if (txSeqs.length === 0) {
                return [
                    { txHash: '', rootHash },
                    new Error('Failed to get txSeqs'),
                ];
            }
            console.log('Transaction sequence number:', txSeqs[0]);
            txSeq = txSeqs[0];
            info = await this.waitForLogEntry(txSeq, false);
        }
        const txHash = receipt ? receipt.hash : '';
        if (info === null) {
            return [{ txHash, rootHash }, new Error('Failed to get log entry')];
        }
        const tasks = await this.splitTasks(info, tree, opts);
        if (tasks === null) {
            return [
                { txHash, rootHash },
                new Error('Failed to get upload tasks'),
            ];
        }
        if (tasks.length === 0) {
            return [{ txHash, rootHash }, null];
        }
        console.log('Processing tasks in parallel with ', tasks.length, ' tasks...');
        const results = await this.processTasksInParallel(file, tree, tasks, retryOpts);
        // Check if any task failed
        for (let i = 0; i < results.length; i++) {
            if (results[i] instanceof Error) {
                return [{ txHash, rootHash }, results[i]];
            }
        }
        console.log('All tasks processed');
        await this.waitForLogEntry(info.tx.seq, true);
        return [{ txHash, rootHash }, null];
    }
    async submitTransaction(submission, opts, retryOpts) {
        let marketAddr = await this.flow.market();
        let marketContract = getMarketContract(marketAddr, this.provider);
        let pricePerSector = await marketContract.pricePerSector();
        let fee = BigInt('0');
        if (opts.fee > 0) {
            fee = opts.fee;
        }
        else {
            fee = calculatePrice(submission, pricePerSector);
        }
        var txOpts = {
            value: fee,
            nonce: opts.nonce,
        };
        if (this.gasPrice > 0) {
            txOpts.gasPrice = this.gasPrice;
        }
        else {
            let suggestedGasPrice = (await this.provider.getFeeData()).gasPrice;
            if (suggestedGasPrice === null) {
                return [
                    null,
                    new Error('Failed to get suggested gas price, set your own gas price'),
                ];
            }
            txOpts.gasPrice = suggestedGasPrice;
        }
        if (this.gasLimit > 0) {
            txOpts.gasLimit = this.gasLimit;
        }
        console.log('Submitting transaction with storage fee:', fee);
        var [txReceipt, txErr] = await txWithGasAdjustment(this.flow, this.provider, 'submit', [submission], txOpts, retryOpts);
        if (txReceipt === null || txErr !== null) {
            return [null, new Error('Failed to submit transaction: ' + txErr)];
        }
        return [txReceipt, null];
    }
    async findExistingFileInfo(rootHash) {
        console.log('Attempting to find existing file info by root hash...');
        // Try to get file info from storage nodes
        for (let client of this.nodes) {
            try {
                const info = await client.getFileInfo(rootHash, false);
                if (info !== null) {
                    console.log('Found existing file info:', info);
                    return info;
                }
            }
            catch (e) {
                console.log('Failed to get file info from node:', client.url);
            }
        }
        return null;
    }
    async processLogs(receipt) {
        const contractAddress = (await this.flow.getAddress()).toLowerCase();
        const signature = this.flow.interface.getEvent('Submit');
        var txSeqs = [];
        for (const log of receipt.logs) {
            // Only process logs that are emitted by this contract.
            if (log.address.toLowerCase() !== contractAddress) {
                continue;
            }
            if (log.topics[0] !== signature.topicHash) {
                continue;
            }
            try {
                // Use the contract's interface to parse the log.
                const parsedLog = this.flow.interface.parseLog(log);
                if (!parsedLog) {
                    continue;
                }
                // Check if the event name is "Submit"
                if (parsedLog.name === 'Submit') {
                    const event = parsedLog.args;
                    txSeqs.push(Number(event.submissionIndex));
                }
            }
            catch (error) {
                // If parseLog fails, this log is not one of our events.
                // You can log the error if needed.
                // console.error("Error decoding log:", error);
                continue;
            }
        }
        return txSeqs;
    }
    async waitForReceipt(txHash, opts) {
        var receipt = null;
        if (opts === undefined) {
            opts = { Retries: 10, Interval: 5, MaxGasPrice: 0 };
        }
        let nTries = 0;
        while (nTries < opts.Retries) {
            receipt = await this.provider.getTransactionReceipt(txHash);
            if (receipt !== null && receipt.status == 1) {
                return receipt;
            }
            await delay(opts.Interval * 1000);
            nTries++;
        }
        return null;
    }
    async waitForLogEntry(txSeq, finalityRequired) {
        console.log('Wait for log entry on storage node');
        let info = null;
        while (true) {
            await delay(1000);
            let ok = true;
            for (let client of this.nodes) {
                info = await client.getFileInfoByTxSeq(txSeq);
                if (info === null) {
                    let logMsg = 'Log entry is unavailable yet';
                    let status = await client.getStatus();
                    if (status !== null) {
                        const logSyncHeight = status.logSyncHeight;
                        logMsg = `Log entry is unavailable yet, zgsNodeSyncHeight=${logSyncHeight}`;
                    }
                    console.log(logMsg);
                    ok = false;
                    break;
                }
                if (finalityRequired && !info.finalized) {
                    console.log('Log entry is available, but not finalized yet, ', client, info);
                    ok = false;
                    break;
                }
            }
            if (ok) {
                break;
            }
        }
        return info;
    }
    // Function to process all tasks in parallel
    async processTasksInParallel(file, tree, tasks, retryOpts) {
        const taskPromises = tasks.map((task) => this.uploadTask(file, tree, task, retryOpts));
        return await Promise.all(taskPromises);
    }
    nextSgmentIndex(config, startIndex) {
        if (config.numShard < 2) {
            return startIndex;
        }
        return (Math.floor((startIndex + config.numShard - 1 - config.shardId) /
            config.numShard) *
            config.numShard +
            config.shardId);
    }
    async splitTasks(info, tree, opts) {
        const shardConfigs = await getShardConfigs(this.nodes);
        if (shardConfigs === null) {
            console.log('Failed to get shard configs');
            return null;
        }
        if (!checkReplica(shardConfigs, opts.expectedReplica)) {
            console.log('Not enough replicas');
            return null;
        }
        let txSeq = info.tx.seq;
        let [startSegmentIndex, endSegmentIndex] = SegmentRange(info.tx.startEntryIndex, info.tx.size);
        var uploadTasks = [];
        for (let clientIndex = 0; clientIndex < shardConfigs.length; clientIndex++) {
            const shardConfig = shardConfigs[clientIndex];
            let cInfo = await this.nodes[clientIndex].getFileInfo(tree.rootHash(), true);
            if (cInfo !== null && cInfo.finalized) {
                console.log('File already exists on node', this.nodes[clientIndex].url, cInfo);
                continue;
            }
            var tasks = [];
            let segIndex = this.nextSgmentIndex(shardConfig, startSegmentIndex);
            while (segIndex <= endSegmentIndex) {
                tasks.push({
                    clientIndex,
                    taskSize: opts.taskSize,
                    segIndex: segIndex - startSegmentIndex,
                    numShard: shardConfig.numShard,
                    txSeq,
                });
                segIndex += shardConfig.numShard * opts.taskSize;
            }
            if (tasks.length > 0) {
                uploadTasks.push(tasks);
            }
        }
        if (uploadTasks.length === 0) {
            return [];
        }
        console.log('Tasks created:', uploadTasks);
        var tasks = [];
        if (uploadTasks.length > 0) {
            uploadTasks.sort((a, b) => a.length - b.length);
            for (let taskIndex = 0; taskIndex < uploadTasks[0].length; taskIndex += 1) {
                for (let i = 0; i < uploadTasks.length && taskIndex < uploadTasks[i].length; i += 1) {
                    tasks.push(uploadTasks[i][taskIndex]);
                }
            }
        }
        return tasks;
    }
    async getSegment(file, tree, segIndex) {
        let numChunks = file.numChunks();
        let startSegIndex = segIndex * DEFAULT_SEGMENT_MAX_CHUNKS;
        if (startSegIndex >= numChunks) {
            return [true, null, null];
        }
        const iter = file.iterateWithOffsetAndBatch(segIndex * DEFAULT_SEGMENT_SIZE, DEFAULT_SEGMENT_SIZE, true);
        let [ok, err] = await iter.next();
        if (!ok) {
            return [false, null, err];
        }
        let segment = iter.current();
        const proof = tree.proofAt(segIndex);
        const startIndex = segIndex * DEFAULT_SEGMENT_MAX_CHUNKS;
        let allDataUploaded = false;
        if (startIndex + segment.length / DEFAULT_CHUNK_SIZE >= numChunks) {
            const expectedLen = DEFAULT_CHUNK_SIZE * (numChunks - startIndex);
            segment = segment.slice(0, expectedLen);
            allDataUploaded = true;
        }
        const segWithProof = {
            root: tree.rootHash(),
            data: encodeBase64(segment),
            index: segIndex,
            proof: proof,
            fileSize: file.size(),
        };
        return [allDataUploaded, segWithProof, null];
    }
    async uploadTask(file, tree, uploadTask, retryOpts) {
        let segIndex = uploadTask.segIndex;
        var segments = [];
        for (let i = 0; i < uploadTask.taskSize; i += 1) {
            let [allDataUploaded, segWithProof, err] = await this.getSegment(file, tree, segIndex);
            if (err !== null) {
                return err;
            }
            if (segWithProof !== null) {
                segments.push(segWithProof);
            }
            if (allDataUploaded) {
                break;
            }
            segIndex += uploadTask.numShard;
        }
        // Retry logic for "too many data writing" errors
        const maxRetries = retryOpts?.TooManyDataRetries ?? 3; // Default to 3 retries
        let attempt = 0;
        let lastError = null;
        while (attempt < maxRetries) {
            try {
                let res = await this.nodes[uploadTask.clientIndex].uploadSegmentsByTxSeq(segments, uploadTask.txSeq);
                if (res === null) {
                    throw new Error(`Node ${this.nodes[uploadTask.clientIndex].url} returned null for upload segments`);
                }
                return res;
            }
            catch (error) {
                lastError = error;
                const nodeUrl = this.nodes[uploadTask.clientIndex].url;
                // Handle "already uploaded and finalized" as success
                if (this.isAlreadyUploadedError(error)) {
                    console.log(`Segments already uploaded and finalized on node ${nodeUrl}`);
                    return 0; // Return success
                }
                // Handle retryable errors
                if (this.isRetryableError(error)) {
                    if (attempt < maxRetries - 1) {
                        const waitTime = (retryOpts?.Interval ?? 3) * 1000 * (attempt + 1);
                        const errorType = this.getErrorType(error);
                        console.log(`${errorType} on attempt ${attempt + 1}/${maxRetries}. Retrying in ${waitTime / 1000}s...`);
                        await new Promise((resolve) => setTimeout(resolve, waitTime));
                        attempt++;
                        continue;
                    }
                    else {
                        const errorMessage = error instanceof Error
                            ? error.message
                            : String(error);
                        console.log(`Max retries (${maxRetries}) reached for error: ${errorMessage}`);
                        return new Error(`Failed after ${maxRetries} attempts: ${errorMessage}`);
                    }
                }
                else {
                    // Non-retryable error - fail immediately
                    const errorMessage = error instanceof Error ? error.message : String(error);
                    console.log(`Non-retryable error encountered: ${errorMessage}`);
                    return lastError;
                }
            }
        }
        const finalError = lastError ||
            new Error(`Upload failed after ${maxRetries} attempts to node ${this.nodes[uploadTask.clientIndex].url}`);
        console.log(`Upload task failed completely:`, finalError.message);
        return finalError;
    }
    isAlreadyUploadedError(error) {
        return (error instanceof Error &&
            (error.data?.includes?.('already uploaded and finalized') ||
                (error.message.includes('Invalid params') &&
                    error.data === 'already uploaded and finalized')));
    }
    isRetryableError(error) {
        return (error instanceof Error &&
            (error.message.includes('too many data writing') ||
                error.message.includes('returned null for upload segments') ||
                error.data?.message?.includes('too many data writing')));
    }
    getErrorType(error) {
        if (error.message.includes('too many data writing')) {
            return '"too many data writing" error';
        }
        else if (error.message.includes('returned null')) {
            return 'null response error';
        }
        else {
            return 'retryable error';
        }
    }
}
//# sourceMappingURL=Uploader.js.map
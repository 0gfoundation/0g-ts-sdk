"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Uploader = void 0;
const constant_js_1 = require("../constant.js");
const utils_js_1 = require("../utils.js");
const ethers_1 = require("ethers");
const utils_js_2 = require("./utils.js");
const index_js_1 = require("../common/index.js");
class Uploader {
    nodes;
    provider;
    flow;
    gasPrice;
    gasLimit;
    constructor(nodes, providerRpc, flow, gasPrice = BigInt('0'), gasLimit = BigInt('0')) {
        this.nodes = nodes;
        this.provider = new ethers_1.ethers.JsonRpcProvider(providerRpc);
        this.flow = flow;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
    }
    async checkExistence(root) {
        for (let client of this.nodes) {
            let info = await client.getFileInfo(root, true);
            if (info !== null && info.finalized) {
                return true;
            }
        }
        return false;
    }
    async uploadFile(file, opts, retryOpts) {
        var [tree, err] = await file.merkleTree();
        if (err != null || tree == null || tree.rootHash() == null) {
            return ['', new Error('Failed to create Merkle tree')];
        }
        console.log('Data prepared to upload', 'root=' + tree.rootHash(), 'size=' + file.size(), 'numSegments=' + file.numSegments(), 'numChunks=' + file.numChunks());
        const exist = await this.checkExistence(tree.rootHash());
        if (exist) {
            return ['', new Error('Data already exists')];
        }
        var [submission, err] = await file.createSubmission(opts.tags);
        if (err !== null || submission === null) {
            return ['', new Error('Failed to create submission')];
        }
        let marketAddr = await this.flow.market();
        let marketContract = (0, utils_js_1.getMarketContract)(marketAddr, this.provider);
        let pricePerSector = await marketContract.pricePerSector();
        let fee = BigInt('0');
        if (opts.fee > 0) {
            fee = opts.fee;
        }
        else {
            fee = (0, utils_js_2.calculatePrice)(submission, pricePerSector);
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
                    '',
                    new Error('Failed to get suggested gas price, set your own gas price'),
                ];
            }
            txOpts.gasPrice = suggestedGasPrice;
        }
        if (this.gasLimit > 0) {
            txOpts.gasLimit = this.gasLimit;
        }
        console.log('Submitting transaction with storage fee:', fee);
        var [receipt, err] = await (0, utils_js_1.txWithGasAdjustment)(this.flow, this.provider, 'submit', [submission], txOpts, retryOpts);
        if (receipt === null || err !== null) {
            return ['', new Error('Failed to submit transaction: ' + err)];
        }
        console.log('Transaction hash:', receipt.hash);
        const txSeqs = await this.processLogs(receipt);
        if (txSeqs.length === 0) {
            return ['', new Error('Failed to get txSeqs')];
        }
        console.log('Transaction sequence number:', txSeqs[0]);
        let info = await this.waitForLogEntry(txSeqs[0], false);
        if (info === null) {
            return ['', new Error('Failed to get log entry')];
        }
        const tasks = await this.segmentUpload(info, file, tree, opts);
        if (tasks === null) {
            return ['', new Error('Failed to get upload tasks')];
        }
        console.log('Processing tasks in parallel with ', tasks.length, ' tasks...');
        err = await this.processTasksInParallel(file, tree, tasks, retryOpts);
        if (err !== null) {
            return ['', err];
        }
        await this.waitForLogEntry(info.tx.seq, true);
        return [receipt.hash, null];
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
    async waitForLogEntry(txSeq, finalityRequired) {
        console.log('Wait for log entry on storage node');
        let info = null;
        while (true) {
            await (0, utils_js_1.delay)(1000);
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
        try {
            const results = await Promise.all(taskPromises);
            // Check if any task failed
            const errors = results.filter(result => result instanceof Error);
            if (errors.length > 0) {
                console.log(`${errors.length} out of ${results.length} tasks failed`);
                // Return the first error found
                return errors[0];
            }
            console.log('All tasks processed successfully');
            return null;
        }
        catch (error) {
            return error instanceof Error ? error : new Error(String(error));
        }
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
    async segmentUpload(info, file, tree, opts) {
        const shardConfigs = await (0, utils_js_2.getShardConfigs)(this.nodes);
        if (shardConfigs === null) {
            console.log('Failed to get shard configs');
            return null;
        }
        if (!(0, index_js_1.checkReplica)(shardConfigs, opts.expectedReplica)) {
            console.log('Not enough replicas');
            return null;
        }
        let txSeq = info.tx.seq;
        let [startSegmentIndex, endSegmentIndex] = (0, utils_js_1.SegmentRange)(info.tx.startEntryIndex, info.tx.size);
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
            return null;
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
        let startSegIndex = segIndex * constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS;
        if (startSegIndex >= numChunks) {
            return [true, null, null];
        }
        const iter = file.iterateWithOffsetAndBatch(segIndex * constant_js_1.DEFAULT_SEGMENT_SIZE, constant_js_1.DEFAULT_SEGMENT_SIZE, true);
        let [ok, err] = await iter.next();
        if (!ok) {
            return [false, null, err];
        }
        let segment = iter.current();
        const proof = tree.proofAt(segIndex);
        const startIndex = segIndex * constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS;
        let allDataUploaded = false;
        if (startIndex + segment.length / constant_js_1.DEFAULT_CHUNK_SIZE >= numChunks) {
            const expectedLen = constant_js_1.DEFAULT_CHUNK_SIZE * (numChunks - startIndex);
            segment = segment.slice(0, expectedLen);
            allDataUploaded = true;
        }
        const segWithProof = {
            root: tree.rootHash(),
            data: (0, ethers_1.encodeBase64)(segment),
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
        const maxRetries = retryOpts?.TooManyDataRetries ?? 3;
        const retryInterval = retryOpts?.Interval ?? 5;
        if (segments.length === 0) {
            console.log(`No segments to upload for task - all data already uploaded`);
            return 0; // Success, but no work to do
        }
        console.log(`Uploading ${segments.length} segments to node ${this.nodes[uploadTask.clientIndex].url} for txSeq ${uploadTask.txSeq}`);
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                let res = await this.nodes[uploadTask.clientIndex].uploadSegmentsByTxSeq(segments, uploadTask.txSeq);
                if (res === null) {
                    const errorMsg = `Failed to upload segments to node ${this.nodes[uploadTask.clientIndex].url} - received null response`;
                    console.log(errorMsg);
                    return new Error(errorMsg);
                }
                return res;
            }
            catch (error) {
                console.log(`Upload error (attempt ${attempt + 1}/${maxRetries + 1}) to node ${this.nodes[uploadTask.clientIndex].url}:`, error.message || error);
                const errorMessage = error?.message?.toLowerCase() || '';
                const isTooManyDataError = errorMessage.includes('too many data writing');
                if (isTooManyDataError && attempt < maxRetries) {
                    console.log(`Too many data writing error, retrying... (attempt ${attempt + 1}/${maxRetries})`);
                    await (0, utils_js_1.delay)(retryInterval * 1000);
                    continue;
                }
                else {
                    return error instanceof Error ? error : new Error(String(error));
                }
            }
        }
        // This should never be reached, but just in case
        return new Error('Failed to upload segments after all retries');
    }
}
exports.Uploader = Uploader;
//# sourceMappingURL=Uploader.js.map
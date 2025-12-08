"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Indexer = void 0;
const tslib_1 = require("tslib");
const open_jsonrpc_provider_1 = require("open-jsonrpc-provider");
const index_js_1 = require("../common/index.js");
const index_js_2 = require("../transfer/index.js");
const index_js_3 = require("../node/index.js");
const utils_js_1 = require("../utils.js");
const fs = tslib_1.__importStar(require("fs"));
class Indexer extends open_jsonrpc_provider_1.HttpProvider {
    constructor(url) {
        super({ url });
    }
    async getShardedNodes() {
        const res = await super.request({
            method: 'indexer_getShardedNodes',
        });
        return res;
    }
    async getNodeLocations() {
        const res = await super.request({
            method: 'indexer_getNodeLocations',
        });
        return res;
    }
    async getFileLocations(rootHash) {
        const res = await super.request({
            method: 'indexer_getFileLocations',
            params: [rootHash],
        });
        return res;
    }
    async newUploaderFromIndexerNodes(blockchain_rpc, signer, expectedReplica, opts) {
        let [clients, err] = await this.selectNodes(expectedReplica);
        if (err != null) {
            return [null, err];
        }
        let status = await clients[0].getStatus();
        if (status == null) {
            return [
                null,
                new Error('failed to get status from the selected node'),
            ];
        }
        console.log('First selected node status :', status);
        let flow = (0, utils_js_1.getFlowContract)(status.networkIdentity.flowAddress, signer);
        console.log('Selected nodes:', clients);
        let uploader = new index_js_2.Uploader(clients, blockchain_rpc, flow, opts?.gasPrice, opts?.gasLimit);
        return [uploader, null];
    }
    async selectNodes(expectedReplica) {
        let nodes = await this.getShardedNodes();
        let [trusted, ok] = (0, index_js_1.selectNodes)(nodes.trusted, expectedReplica);
        if (!ok) {
            return [
                [],
                new Error('cannot select a subset from the returned nodes that meets the replication requirement'),
            ];
        }
        let clients = [];
        trusted.forEach((node) => {
            let sn = new index_js_3.StorageNode(node.url);
            clients.push(sn);
        });
        return [clients, null];
    }
    async upload(file, blockchain_rpc, signer, uploadOpts, retryOpts, opts) {
        console.log(`Starting upload for file of size: ${file.size()} bytes`);
        const mergedOpts = (0, index_js_2.mergeUploadOptions)(uploadOpts);
        console.log(`Upload options:`, mergedOpts);
        let [uploader, err] = await this.newUploaderFromIndexerNodes(blockchain_rpc, signer, mergedOpts.expectedReplica, opts);
        if (err != null || uploader == null) {
            console.error(`Failed to create uploader: ${err?.message}`);
            return [{ txHash: '', rootHash: '' }, err];
        }
        console.log(`Using splitable upload (handles both single and fragment cases)`);
        // Add debugging info before upload
        console.log(`File details - size: ${file.size()}, numSegments: ${file.numSegments()}, numChunks: ${file.numChunks()}`);
        const [result, uploadErr] = await uploader.splitableUpload(file, mergedOpts, retryOpts);
        if (uploadErr != null) {
            console.error(`Upload failed with error:`, uploadErr.message);
            console.error(`Error stack:`, uploadErr.stack);
            return [{ txHash: '', rootHash: '' }, uploadErr];
        }
        // Check if it's a single file result (array with one element) or multiple fragments
        if (result.txHashes.length === 1 && result.rootHashes.length === 1) {
            console.log(`Single file upload completed - returning single result`);
            return [
                {
                    txHash: result.txHashes[0],
                    rootHash: result.rootHashes[0],
                },
                null,
            ];
        }
        else {
            console.log(`Fragment upload completed - returning ${result.txHashes.length} fragments`);
            return [result, null];
        }
    }
    /**
     * Implementation
     */
    async download(rootHashOrHashes, filePath, proof = false) {
        console.log(`Starting download to: ${filePath}, proof: ${proof}`);
        if (Array.isArray(rootHashOrHashes)) {
            // Handle multiple files - download fragments sequentially
            console.log(`Downloading ${rootHashOrHashes.length} fragments:`, rootHashOrHashes);
            return await this.downloadFragments(rootHashOrHashes, filePath, proof);
        }
        else {
            // Handle single file
            console.log(`Downloading single file with root hash: ${rootHashOrHashes}`);
            return await this.downloadSingle(rootHashOrHashes, filePath, proof);
        }
    }
    /**
     * Downloads fragments sequentially to temp files and concatenates them
     */
    async downloadFragments(rootHashes, filePath, proof) {
        // Create output file
        let outFile;
        try {
            outFile = fs.createWriteStream(filePath);
        }
        catch (err) {
            return new Error(`Failed to create output file: ${err instanceof Error ? err.message : String(err)}`);
        }
        try {
            for (const rootHash of rootHashes) {
                console.log(`Processing fragment: ${rootHash}`);
                // Create temp file for this fragment
                const tempFile = `${rootHash}.temp`;
                // Create downloader for this specific root hash
                const [downloader, err] = await this.newDownloaderFromIndexerNodes(rootHash);
                if (err !== null || downloader === null) {
                    outFile.destroy();
                    return new Error(`Failed to create downloader for ${rootHash}: ${err?.message}`);
                }
                // Download to temp file
                const downloadErr = await downloader.download(rootHash, tempFile, proof);
                if (downloadErr !== null) {
                    outFile.destroy();
                    return new Error(`Failed to download fragment ${rootHash}: ${downloadErr.message}`);
                }
                // Copy temp file content to output file
                try {
                    const inFile = fs.createReadStream(tempFile);
                    await new Promise((resolve, reject) => {
                        inFile.pipe(outFile, { end: false });
                        inFile.on('end', resolve);
                        inFile.on('error', reject);
                    });
                }
                catch (err) {
                    outFile.destroy();
                    return new Error(`Failed to copy content from temp file ${tempFile}: ${err instanceof Error ? err.message : String(err)}`);
                }
                // Clean up temp file
                try {
                    fs.unlinkSync(tempFile);
                }
                catch (err) {
                    console.warn(`Failed to delete temp file ${tempFile}: ${err instanceof Error ? err.message : String(err)}`);
                }
            }
            outFile.end();
            return null;
        }
        catch (err) {
            outFile.destroy();
            return new Error(`Fragment download failed: ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    /**
     * Downloads a single file
     */
    async downloadSingle(rootHash, filePath, proof) {
        const [downloader, err] = await this.newDownloaderFromIndexerNodes(rootHash);
        if (err !== null || downloader === null) {
            return new Error(`Failed to create downloader: ${err?.message}`);
        }
        return await downloader.download(rootHash, filePath, proof);
    }
    /**
     * Creates a new downloader from indexer nodes for the given root hash
     */
    async newDownloaderFromIndexerNodes(rootHash) {
        console.log(`Getting file locations for root hash: ${rootHash}`);
        const locations = await this.getFileLocations(rootHash);
        console.log(`Found ${locations.length} locations for ${rootHash}:`, locations.map((l) => l.url));
        if (locations.length === 0) {
            console.error(`No locations found for root hash: ${rootHash}`);
            return [
                null,
                new Error(`Failed to get file locations for ${rootHash}`),
            ];
        }
        const clients = [];
        locations.forEach((node) => {
            const sn = new index_js_3.StorageNode(node.url);
            clients.push(sn);
        });
        console.log(`Created ${clients.length} storage clients for ${rootHash}`);
        const downloader = new index_js_2.Downloader(clients);
        return [downloader, null];
    }
}
exports.Indexer = Indexer;
//# sourceMappingURL=Indexer.js.map
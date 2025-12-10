"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Downloader = void 0;
const tslib_1 = require("tslib");
const fs_1 = tslib_1.__importDefault(require("fs"));
const path_1 = tslib_1.__importDefault(require("path"));
const constant_js_1 = require("../constant.js");
const utils_js_1 = require("../utils.js");
const ethers_1 = require("ethers");
const utils_js_2 = require("./utils.js");
class Downloader {
    nodes;
    shardConfigs;
    startSegmentIndex;
    endSegmentIndex;
    constructor(nodes) {
        this.nodes = nodes;
        this.shardConfigs = [];
        this.startSegmentIndex = 0;
        this.endSegmentIndex = 0;
    }
    /**
     * Implementation
     */
    async download(rootOrRoots, filePath, proof = false) {
        if (Array.isArray(rootOrRoots)) {
            return this.downloadFragments(rootOrRoots, filePath, proof);
        }
        else {
            return this.downloadFile(rootOrRoots, filePath, proof);
        }
    }
    async downloadFile(root, filePath, proof) {
        var [info, err] = await this.queryFile(root);
        if (err != null || info === null) {
            return new Error(err?.message);
        }
        if (!info.finalized) {
            return new Error('File not finalized');
        }
        if ((0, utils_js_1.checkExist)(filePath)) {
            return new Error('Wrong path, provide a file path which does not exist.');
        }
        let shardConfigs = await (0, utils_js_2.getShardConfigs)(this.nodes);
        if (shardConfigs === null) {
            return new Error('Failed to get shard configs');
        }
        this.shardConfigs = shardConfigs;
        err = await this.downloadFileHelper(filePath, info, proof);
        return err;
    }
    /**
     * Downloads multiple files by their root hashes and concatenates them into a single output file
     * @param roots Array of root hashes to download
     * @param filename Output file path where concatenated data will be written
     * @param withProof Whether to include proof verification during download
     * @returns Promise that resolves to Error if any operation fails, null on success
     */
    async downloadFragments(roots, filename, withProof = false) {
        // Check if output file already exists
        if ((0, utils_js_1.checkExist)(filename)) {
            return new Error('Output file already exists. Provide a file path which does not exist.');
        }
        // Ensure output directory exists
        const outputDir = path_1.default.dirname(filename);
        if (!fs_1.default.existsSync(outputDir)) {
            try {
                fs_1.default.mkdirSync(outputDir, { recursive: true });
            }
            catch (err) {
                return new Error(`Failed to create output directory: ${err}`);
            }
        }
        // Create output file stream
        let outFileHandle;
        try {
            outFileHandle = fs_1.default.openSync(filename, 'w');
        }
        catch (err) {
            return new Error(`Failed to create output file: ${err}`);
        }
        const tempFiles = [];
        try {
            for (const root of roots) {
                // Generate temporary file name
                const tempFile = path_1.default.join(outputDir, `${root}.temp`);
                tempFiles.push(tempFile);
                // Download individual file
                const downloadErr = await this.downloadFile(root, tempFile, withProof);
                if (downloadErr != null) {
                    return new Error(`Failed to download file with root ${root}: ${downloadErr.message}`);
                }
                // Read and append temp file content to output file
                try {
                    const data = fs_1.default.readFileSync(tempFile);
                    fs_1.default.writeSync(outFileHandle, new Uint8Array(data));
                }
                catch (err) {
                    return new Error(`Failed to copy content from temp file ${tempFile}: ${err}`);
                }
                // Clean up temp file immediately after processing
                try {
                    fs_1.default.unlinkSync(tempFile);
                }
                catch (err) {
                    console.warn(`Warning: failed to delete temp file ${tempFile}: ${err}`);
                    // Don't fail the entire operation for cleanup issues
                }
            }
            return null;
        }
        catch (err) {
            return new Error(`Unexpected error during download fragments: ${err}`);
        }
        finally {
            // Ensure output file is closed
            try {
                fs_1.default.closeSync(outFileHandle);
            }
            catch (err) {
                console.warn(`Warning: failed to close output file: ${err}`);
            }
            // Clean up any remaining temp files
            for (const tempFile of tempFiles) {
                try {
                    if (fs_1.default.existsSync(tempFile)) {
                        fs_1.default.unlinkSync(tempFile);
                    }
                }
                catch (err) {
                    console.warn(`Warning: failed to clean up temp file ${tempFile}: ${err}`);
                }
            }
        }
    }
    async queryFile(root) {
        let fileInfo = null;
        for (let node of this.nodes) {
            const currInfo = await node.getFileInfo(root, true);
            if (currInfo === null) {
                return [null, new Error('File not found on node ' + node.url)];
            }
            else if (fileInfo === null) {
                fileInfo = currInfo;
            }
        }
        return [fileInfo, null];
    }
    // TODO: add proof check
    async downloadTask(info, segmentOffset, taskInd, numChunks, proof) {
        const segmentIndex = segmentOffset + taskInd;
        const startIndex = segmentIndex * constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS;
        var endIndex = startIndex + constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS;
        if (endIndex > numChunks) {
            endIndex = numChunks;
        }
        let segment = null;
        for (let i = 0; i < this.shardConfigs.length; i++) {
            let nodeIndex = (taskInd + i) % this.shardConfigs.length;
            if ((this.startSegmentIndex + segmentIndex) %
                this.shardConfigs[nodeIndex].numShard !=
                this.shardConfigs[nodeIndex].shardId) {
                continue;
            }
            // try download from current node
            segment = await this.nodes[nodeIndex].downloadSegmentByTxSeq(info.tx.seq, startIndex, endIndex);
            if (segment === null) {
                continue;
            }
            var segArray = (0, ethers_1.decodeBase64)(segment);
            if (this.startSegmentIndex + segmentIndex == this.endSegmentIndex) {
                const lastChunkSize = info.tx.size % constant_js_1.DEFAULT_CHUNK_SIZE;
                if (lastChunkSize > 0) {
                    const paddings = constant_js_1.DEFAULT_CHUNK_SIZE - lastChunkSize;
                    segArray = segArray.slice(0, segArray.length - paddings);
                }
            }
            return [segArray, null];
        }
        return [
            new Uint8Array(),
            new Error('No storage node holds segment with index ' + segmentIndex),
        ];
    }
    async downloadFileHelper(filePath, info, proof) {
        const segmentOffset = 0;
        const numChunks = (0, utils_js_1.GetSplitNum)(info.tx.size, constant_js_1.DEFAULT_CHUNK_SIZE);
        this.startSegmentIndex = Math.floor(info.tx.startEntryIndex / constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS);
        this.endSegmentIndex = Math.floor((info.tx.startEntryIndex +
            (0, utils_js_1.GetSplitNum)(info.tx.size, constant_js_1.DEFAULT_CHUNK_SIZE) -
            1) /
            constant_js_1.DEFAULT_SEGMENT_MAX_CHUNKS);
        const numTasks = this.endSegmentIndex - this.startSegmentIndex + 1;
        for (let taskInd = 0; taskInd < numTasks; taskInd++) {
            let [segArray, err] = await this.downloadTask(info, segmentOffset, taskInd, numChunks, proof);
            if (err != null) {
                return err;
            }
            fs_1.default.appendFileSync(filePath, segArray);
        }
        return null;
    }
}
exports.Downloader = Downloader;
//# sourceMappingURL=Downloader.js.map
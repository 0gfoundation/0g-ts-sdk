"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Indexer = void 0;
const open_jsonrpc_provider_1 = require("open-jsonrpc-provider");
const index_js_1 = require("../common/index.js");
const index_js_2 = require("../transfer/index.js");
const index_js_3 = require("../node/index.js");
const utils_js_1 = require("../utils.js");
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
        var expectedReplica = 1;
        if (uploadOpts != undefined && uploadOpts.expectedReplica != null) {
            expectedReplica = Math.max(1, uploadOpts.expectedReplica);
        }
        let [uploader, err] = await this.newUploaderFromIndexerNodes(blockchain_rpc, signer, expectedReplica, opts);
        if (err != null || uploader == null) {
            return [{ txHash: '', rootHash: '' }, err];
        }
        if (uploadOpts === undefined) {
            uploadOpts = {
                tags: '0x',
                finalityRequired: true,
                taskSize: 10,
                expectedReplica: 1,
                skipTx: false,
                fee: BigInt('0'),
            };
        }
        return await uploader.uploadFile(file, uploadOpts, retryOpts);
    }
    async download(rootHash, filePath, proof) {
        let locations = await this.getFileLocations(rootHash);
        if (locations.length == 0) {
            return new Error('failed to get file locations');
        }
        let clients = [];
        locations.forEach((node) => {
            let sn = new index_js_3.StorageNode(node.url);
            clients.push(sn);
        });
        let downloader = new index_js_2.Downloader(clients);
        return await downloader.downloadFile(rootHash, filePath, proof);
    }
}
exports.Indexer = Indexer;
//# sourceMappingURL=Indexer.js.map
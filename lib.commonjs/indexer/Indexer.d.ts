import { HttpProvider } from 'open-jsonrpc-provider';
import { IpLocation, ShardedNodes, TransactionOptions } from './types.js';
import { ShardedNode } from '../common/index.js';
import { UploadOption, Uploader } from '../transfer/index.js';
import { StorageNode } from '../node/index.js';
import { RetryOpts } from '../types.js';
import { AbstractFile } from '../file/AbstractFile.js';
import { Signer } from 'ethers';
export declare class Indexer extends HttpProvider {
    constructor(url: string);
    getShardedNodes(): Promise<ShardedNodes>;
    getNodeLocations(): Promise<Map<string, IpLocation>>;
    getFileLocations(rootHash: string): Promise<ShardedNode[]>;
    newUploaderFromIndexerNodes(blockchain_rpc: string, signer: Signer, expectedReplica: number, opts?: TransactionOptions): Promise<[Uploader | null, Error | null]>;
    selectNodes(expectedReplica: number): Promise<[StorageNode[], Error | null]>;
    upload(file: AbstractFile, blockchain_rpc: string, signer: Signer, uploadOpts?: UploadOption, retryOpts?: RetryOpts, opts?: TransactionOptions): Promise<[
        ({
            txHash: string;
            rootHash: string;
        } | {
            txHashes: string[];
            rootHashes: string[];
        }),
        Error | null
    ]>;
    /**
     * Downloads a single file by root hash
     */
    download(rootHash: string, filePath: string, proof?: boolean): Promise<Error | null>;
    /**
     * Downloads multiple files by root hashes and concatenates them
     */
    download(rootHashes: string[], filePath: string, proof?: boolean): Promise<Error | null>;
    /**
     * Downloads fragments sequentially to temp files and concatenates them
     */
    private downloadFragments;
    /**
     * Downloads a single file
     */
    private downloadSingle;
    /**
     * Creates a new downloader from indexer nodes for the given root hash
     */
    private newDownloaderFromIndexerNodes;
}
//# sourceMappingURL=Indexer.d.ts.map
import { StorageNode, FileInfo } from '../node/index.js';
import { Hash } from '../types.js';
import { ShardConfig } from '../common/index.js';
export declare class Downloader {
    nodes: StorageNode[];
    shardConfigs: ShardConfig[];
    startSegmentIndex: number;
    endSegmentIndex: number;
    constructor(nodes: StorageNode[]);
    /**
     * Downloads a single file by root hash
     */
    download(root: Hash, filePath: string, proof?: boolean): Promise<Error | null>;
    /**
     * Downloads multiple files by root hashes and concatenates them
     */
    download(roots: Hash[], filePath: string, proof?: boolean): Promise<Error | null>;
    downloadFile(root: Hash, filePath: string, proof: boolean): Promise<Error | null>;
    /**
     * Downloads multiple files by their root hashes and concatenates them into a single output file
     * @param roots Array of root hashes to download
     * @param filename Output file path where concatenated data will be written
     * @param withProof Whether to include proof verification during download
     * @returns Promise that resolves to Error if any operation fails, null on success
     */
    downloadFragments(roots: string[], filename: string, withProof?: boolean): Promise<Error | null>;
    queryFile(root: string): Promise<[FileInfo | null, Error | null]>;
    downloadTask(info: FileInfo, segmentOffset: number, taskInd: number, numChunks: number, proof: boolean): Promise<[Uint8Array, Error | null]>;
    downloadFileHelper(filePath: string, info: FileInfo, proof: boolean): Promise<Error | null>;
}
//# sourceMappingURL=Downloader.d.ts.map
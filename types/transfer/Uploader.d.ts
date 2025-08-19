import { StorageNode, SegmentWithProof, FileInfo } from '../node/index.js';
import { FixedPriceFlow } from '../contracts/flow/FixedPriceFlow.js';
import { RetryOpts } from '../types.js';
import { MerkleTree } from '../file/index.js';
import { ethers } from 'ethers';
import { UploadOption, UploadTask } from './types.js';
import { AbstractFile } from '../file/AbstractFile.js';
import { ShardConfig } from '../common/index.js';
export declare class Uploader {
    nodes: StorageNode[];
    provider: ethers.JsonRpcProvider;
    flow: FixedPriceFlow;
    gasPrice: bigint;
    gasLimit: bigint;
    constructor(nodes: StorageNode[], providerRpc: string, flow: FixedPriceFlow, gasPrice?: bigint, gasLimit?: bigint);
    checkExistence(root: string): Promise<boolean>;
    uploadFile(file: AbstractFile, opts: UploadOption, retryOpts?: RetryOpts): Promise<[string, Error | null]>;
    processLogs(receipt: ethers.TransactionReceipt): Promise<number[]>;
    waitForLogEntry(txSeq: number, finalityRequired: boolean): Promise<FileInfo | null>;
    processTasksInParallel(file: AbstractFile, tree: MerkleTree, tasks: UploadTask[], retryOpts?: RetryOpts): Promise<Error | null>;
    nextSgmentIndex(config: ShardConfig, startIndex: number): number;
    segmentUpload(info: FileInfo, file: AbstractFile, tree: MerkleTree, opts: UploadOption): Promise<UploadTask[] | null>;
    getSegment(file: AbstractFile, tree: MerkleTree, segIndex: number): Promise<[boolean, SegmentWithProof | null, Error | null]>;
    uploadTask(file: AbstractFile, tree: MerkleTree, uploadTask: UploadTask, retryOpts?: RetryOpts): Promise<number | Error>;
}
//# sourceMappingURL=Uploader.d.ts.map
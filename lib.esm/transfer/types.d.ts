import { ethers } from 'ethers';
export interface UploadTask {
    clientIndex: number;
    taskSize: number;
    segIndex: number;
    numShard: number;
    txSeq: number;
}
export interface UploadOption {
    tags?: ethers.BytesLike;
    finalityRequired?: boolean;
    taskSize?: number;
    expectedReplica?: number;
    fragmentSize?: number;
    skipTx?: boolean;
    fee?: bigint;
    nonce?: bigint;
}
export declare const defaultUploadOption: Omit<Required<UploadOption>, 'nonce'> & {
    nonce?: bigint;
};
/**
 * Merges user-provided upload options with default values
 */
export declare function mergeUploadOptions(userOptions?: UploadOption): Required<Omit<UploadOption, 'nonce'>> & {
    nonce?: bigint;
};
//# sourceMappingURL=types.d.ts.map
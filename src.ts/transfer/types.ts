import { ethers } from 'ethers'

export interface UploadTask {
    clientIndex: number
    taskSize: number
    segIndex: number
    numShard: number
    txSeq: number
}

export interface UploadOption {
    tags?: ethers.BytesLike // transaction tags
    finalityRequired?: boolean // wait for file finalized on uploaded nodes or not
    taskSize?: number // number of segment to upload in single rpc request
    expectedReplica?: number // expected number of replications
    fragmentSize?: number // size of each fragment in bytes
    skipTx?: boolean // skip sending transaction on chain, this can set to true only if the data has already settled on chain before
    fee?: bigint // fee to pay for data storage
    nonce?: bigint // nonce for the transaction
}

export const defaultUploadOption: Omit<Required<UploadOption>, 'nonce'> & {
    nonce?: bigint
} = {
    tags: '0x',
    finalityRequired: true,
    taskSize: 1,
    expectedReplica: 1,
    fragmentSize: 1024 * 1024 * 1024 * 4, // 4GB
    skipTx: false,
    fee: BigInt(0),
}

/**
 * Merges user-provided upload options with default values
 */
export function mergeUploadOptions(
    userOptions: UploadOption = {}
): Required<Omit<UploadOption, 'nonce'>> & { nonce?: bigint } {
    return {
        tags: userOptions.tags ?? defaultUploadOption.tags,
        finalityRequired:
            userOptions.finalityRequired ??
            defaultUploadOption.finalityRequired,
        taskSize: userOptions.taskSize ?? defaultUploadOption.taskSize,
        expectedReplica:
            userOptions.expectedReplica ?? defaultUploadOption.expectedReplica,
        fragmentSize:
            userOptions.fragmentSize ?? defaultUploadOption.fragmentSize,
        skipTx: userOptions.skipTx ?? defaultUploadOption.skipTx,
        fee: userOptions.fee ?? defaultUploadOption.fee,
        nonce: userOptions.nonce,
    }
}

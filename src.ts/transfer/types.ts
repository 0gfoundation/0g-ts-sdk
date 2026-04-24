import { ethers } from 'ethers'

export interface UploadTask {
    clientIndex: number
    taskSize: number
    segIndex: number
    numShard: number
    txSeq: number
}

export type EncryptionOption =
    | { type: 'aes256'; key: Uint8Array }
    | { type: 'ecies'; recipientPubKey: Uint8Array | string }

export interface UploadOption {
    tags?: ethers.BytesLike // transaction tags
    submitter?: string // submission submitter address, defaults to runner address
    finalityRequired?: boolean // wait for file finalized on uploaded nodes or not
    taskSize?: number // number of segment to upload in single rpc request
    expectedReplica?: number // expected number of replications
    fragmentSize?: number // size of each fragment in bytes
    skipTx?: boolean // skip sending transaction on chain, this can set to true only if the data has already settled on chain before
    skipIfFinalized?: boolean // skip upload entirely if the file already exists and is finalized on storage nodes
    fee?: bigint // fee to pay for data storage
    nonce?: bigint // nonce for the transaction
    onProgress?: (message: string) => void // optional progress callback
    encryption?: EncryptionOption // optional encryption; 'aes256' uses a caller-supplied 32-byte key (v1), 'ecies' derives the AES key from an ephemeral keypair and the recipient's secp256k1 pubkey (v2)
}

export const defaultUploadOption: Omit<
    Required<UploadOption>,
    'nonce' | 'onProgress' | 'encryption'
> & {
    nonce?: bigint
    onProgress?: (message: string) => void
    encryption?: EncryptionOption
} = {
    tags: '0x',
    submitter: '',
    finalityRequired: true,
    taskSize: 1,
    expectedReplica: 1,
    fragmentSize: 1024 * 1024 * 1024 * 4, // 4GB
    skipTx: false,
    skipIfFinalized: false,
    fee: BigInt(0),
}

/**
 * Merges user-provided upload options with default values
 */
export function mergeUploadOptions(userOptions: UploadOption = {}): Required<
    Omit<UploadOption, 'nonce' | 'onProgress' | 'encryption'>
> & {
    nonce?: bigint
    onProgress?: (message: string) => void
    encryption?: EncryptionOption
} {
    return {
        tags: userOptions.tags ?? defaultUploadOption.tags,
        submitter: userOptions.submitter ?? defaultUploadOption.submitter,
        finalityRequired:
            userOptions.finalityRequired ??
            defaultUploadOption.finalityRequired,
        taskSize: userOptions.taskSize ?? defaultUploadOption.taskSize,
        expectedReplica:
            userOptions.expectedReplica ?? defaultUploadOption.expectedReplica,
        fragmentSize:
            userOptions.fragmentSize ?? defaultUploadOption.fragmentSize,
        skipTx: userOptions.skipTx ?? defaultUploadOption.skipTx,
        skipIfFinalized:
            userOptions.skipIfFinalized ?? defaultUploadOption.skipIfFinalized,
        fee: userOptions.fee ?? defaultUploadOption.fee,
        nonce: userOptions.nonce,
        onProgress: userOptions.onProgress,
        encryption: userOptions.encryption,
    }
}

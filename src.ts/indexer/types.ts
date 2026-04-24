import { ShardedNode } from '../common/types'

export interface IpLocation {
    city: number
    region: string
    country: string
    location: string
    timezone: string
}

export interface ShardedNodes {
    trusted: ShardedNode[]
    discovered: ShardedNode[]
}

export interface TransactionOptions {
    gasPrice?: bigint
    gasLimit?: bigint
}

export interface DownloadOption {
    proof?: boolean
    // Best-effort decryption. If the downloaded file begins with a v1/v2
    // encryption header and the matching key is supplied here, the SDK
    // decrypts in-memory and returns the plaintext. On any mismatch
    // (file not encrypted, wrong key type, malformed header) the SDK
    // silently returns the raw bytes instead of throwing. The caller
    // can use `peekHeader` beforehand to render key-input UI.
    decryption?: {
        symmetricKey?: Uint8Array | string
        privateKey?: Uint8Array | string
    }
}

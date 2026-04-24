import { secp256k1 } from '@noble/curves/secp256k1'
import {
    parseEncryptionHeader,
    resolveDecryptionKey,
    decryptFile,
    decryptFragmentData,
    ECIES_VERSION,
    EncryptionHeader,
} from '../common/encryption.js'

// Best-effort decrypt. If `encrypted` starts with a v1/v2 encryption header
// and the caller supplied the matching key, returns the decrypted plaintext
// and decrypted=true. On any mismatch — the file wasn't encrypted, the
// embedded ephemeral pubkey isn't on-curve, or the key type doesn't match
// the header version — returns the original bytes unchanged with
// decrypted=false. Never throws for decryption-related reasons; any thrown
// error is treated as "not encrypted, fall back".
export function tryDecrypt(
    encrypted: Uint8Array,
    opts: {
        symmetricKey?: Uint8Array
        privateKey?: Uint8Array | string
    }
): { bytes: Uint8Array; decrypted: boolean } {
    if (encrypted.length < 1) {
        return { bytes: encrypted, decrypted: false }
    }

    let header: EncryptionHeader
    try {
        header = parseEncryptionHeader(encrypted)
    } catch {
        return { bytes: encrypted, decrypted: false }
    }

    // Defensive: for v2, confirm the embedded ephemeral pubkey is a valid
    // on-curve secp256k1 point before attempting AES-CTR decrypt. AES-CTR has
    // no authentication, so without this check we could "decrypt" a plain
    // file that happened to start with 0x02 into garbage bytes.
    if (header.version === ECIES_VERSION) {
        try {
            secp256k1.ProjectivePoint.fromHex(header.ephemeralPub)
        } catch {
            return { bytes: encrypted, decrypted: false }
        }
    }

    let aesKey: Uint8Array
    try {
        aesKey = resolveDecryptionKey(
            opts.symmetricKey,
            opts.privateKey,
            header
        )
    } catch {
        // Key material doesn't match this header version (e.g. v2 file but
        // caller only supplied a symmetric key). Treat as "cannot decrypt" and
        // return the raw bytes; caller will see the encrypted blob.
        return { bytes: encrypted, decrypted: false }
    }

    try {
        const plaintext = decryptFile(aesKey, encrypted)
        return { bytes: plaintext, decrypted: true }
    } catch {
        return { bytes: encrypted, decrypted: false }
    }
}

// Best-effort multi-fragment decrypt. Mirrors 0g-storage-client's
// indexer/client.go:390 downloadEncryptedFragments — parses the encryption
// header from fragment 0, resolves the AES key from caller-supplied
// material, then decrypts each subsequent fragment with the correct CTR
// offset so a fragment that starts mid-stream decrypts to the same bytes
// as a full-file decrypt.
//
// Returns an array of plaintext fragments on success, or null if any step
// fails (header missing/malformed, embedded ephemeral pubkey off-curve,
// wrong key material, decrypt error). The caller falls back to the raw
// concatenation in that case.
export function tryDecryptFragments(
    fragments: Uint8Array[],
    symmetricKey: Uint8Array | undefined,
    privateKey: Uint8Array | string | undefined
): Uint8Array[] | null {
    if (fragments.length === 0) return []

    let header: EncryptionHeader
    try {
        header = parseEncryptionHeader(fragments[0])
    } catch {
        return null
    }

    if (header.version === ECIES_VERSION) {
        try {
            secp256k1.ProjectivePoint.fromHex(header.ephemeralPub)
        } catch {
            return null
        }
    }

    let aesKey: Uint8Array
    try {
        aesKey = resolveDecryptionKey(symmetricKey, privateKey, header)
    } catch {
        return null
    }

    const plaintexts: Uint8Array[] = []
    let cumulativeDataOffset = 0
    for (let i = 0; i < fragments.length; i++) {
        try {
            const { plaintext, newOffset } = decryptFragmentData(
                aesKey,
                header,
                fragments[i],
                i === 0,
                cumulativeDataOffset
            )
            plaintexts.push(plaintext)
            cumulativeDataOffset = newOffset
        } catch {
            return null
        }
    }
    return plaintexts
}

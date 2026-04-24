import { secp256k1 } from '@noble/curves/secp256k1'
import {
    parseEncryptionHeader,
    resolveDecryptionKey,
    decryptFile,
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

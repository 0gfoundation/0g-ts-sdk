// Wire-compatible with 0g-storage-client commit 6d39443.
// v1: [version=0x01][nonce:16]                     — 17 bytes
// v2: [version=0x02][ephemeralPub:33][nonce:16]    — 50 bytes

import { ctr } from '@noble/ciphers/aes'
import { secp256k1 } from '@noble/curves/secp256k1'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { randomBytes } from '@noble/hashes/utils'

export const SYMMETRIC_VERSION = 1
export const ECIES_VERSION = 2
export const SYMMETRIC_HEADER_SIZE = 17
export const EPHEMERAL_PUBKEY_SIZE = 33
export const ECIES_HEADER_SIZE = 1 + EPHEMERAL_PUBKEY_SIZE + 16

// Domain-separation string. MUST match the Go client byte-for-byte for interop:
// `var eciesHKDFInfo = []byte("0g-storage-client/ecies/v1/aes-256")`
const ECIES_HKDF_INFO = new TextEncoder().encode(
    '0g-storage-client/ecies/v1/aes-256'
)

export class EncryptionHeader {
    constructor(
        public version: number,
        public nonce: Uint8Array,
        public ephemeralPub: Uint8Array = new Uint8Array(EPHEMERAL_PUBKEY_SIZE)
    ) {
        if (nonce.length !== 16) {
            throw new Error(`nonce must be 16 bytes, got ${nonce.length}`)
        }
        if (ephemeralPub.length !== EPHEMERAL_PUBKEY_SIZE) {
            throw new Error(
                `ephemeralPub must be ${EPHEMERAL_PUBKEY_SIZE} bytes, got ${ephemeralPub.length}`
            )
        }
    }

    size(): number {
        return this.version === ECIES_VERSION
            ? ECIES_HEADER_SIZE
            : SYMMETRIC_HEADER_SIZE
    }

    toBytes(): Uint8Array {
        if (this.version === ECIES_VERSION) {
            const buf = new Uint8Array(ECIES_HEADER_SIZE)
            buf[0] = this.version
            buf.set(this.ephemeralPub, 1)
            buf.set(this.nonce, 1 + EPHEMERAL_PUBKEY_SIZE)
            return buf
        }
        const buf = new Uint8Array(SYMMETRIC_HEADER_SIZE)
        buf[0] = this.version
        buf.set(this.nonce, 1)
        return buf
    }
}

export function parseEncryptionHeader(data: Uint8Array): EncryptionHeader {
    if (data.length < 1) {
        throw new Error(`data too short for encryption header: ${data.length}`)
    }
    const version = data[0]
    switch (version) {
        case SYMMETRIC_VERSION: {
            if (data.length < SYMMETRIC_HEADER_SIZE) {
                throw new Error(
                    `data too short for v1 encryption header: ${data.length} < ${SYMMETRIC_HEADER_SIZE}`
                )
            }
            return new EncryptionHeader(version, data.slice(1, 17))
        }
        case ECIES_VERSION: {
            if (data.length < ECIES_HEADER_SIZE) {
                throw new Error(
                    `data too short for v2 encryption header: ${data.length} < ${ECIES_HEADER_SIZE}`
                )
            }
            return new EncryptionHeader(
                version,
                data.slice(
                    1 + EPHEMERAL_PUBKEY_SIZE,
                    1 + EPHEMERAL_PUBKEY_SIZE + 16
                ),
                data.slice(1, 1 + EPHEMERAL_PUBKEY_SIZE)
            )
        }
        default:
            throw new Error(`unsupported encryption version: ${version}`)
    }
}

// cryptAt encrypts or decrypts data in-place at plaintext byte offset `offset`.
// AES-256-CTR is symmetric — encrypt and decrypt are the same XOR operation.
// counter = nonce + floor(offset/16) big-endian; byteSkip = offset mod 16 bytes
// of keystream are discarded before the XOR so fragment-offset decryption
// produces bit-identical output to a full-file decrypt.
export function cryptAt(
    key: Uint8Array,
    nonce: Uint8Array,
    offset: number,
    data: Uint8Array
): void {
    if (key.length !== 32) throw new Error('key must be 32 bytes')
    if (nonce.length !== 16) throw new Error('nonce must be 16 bytes')
    if (data.length === 0) return

    const blockSize = 16
    const blockOffset = Math.floor(offset / blockSize)
    const byteOffset = offset % blockSize

    const counter = new Uint8Array(16)
    counter.set(nonce)
    addToCounter(counter, blockOffset)

    // @noble/ciphers 1.x ctr is one-shot per instance. Feed
    // byteOffset zero bytes of padding at the front so the XOR aligns with
    // the per-byte offset within the starting block, encrypt once, and
    // discard the padding prefix.
    const padded = new Uint8Array(byteOffset + data.length)
    padded.set(data, byteOffset)
    const cipher = ctr(key, counter)
    const encrypted = cipher.encrypt(padded)
    data.set(encrypted.slice(byteOffset))
}

// Big-endian 128-bit add of `val` into the 16-byte counter (in place).
// val is a non-negative JS number (safe up to 2^53 blocks ≈ 144 PB of
// ciphertext, which is beyond any realistic file size).
function addToCounter(counter: Uint8Array, val: number): void {
    let carry = val
    for (let i = 15; i >= 0 && carry > 0; i--) {
        const sum = counter[i] + (carry & 0xff)
        counter[i] = sum & 0xff
        carry = Math.floor(carry / 256) + (sum > 0xff ? 1 : 0)
    }
}

// Accepts:
//   - 33-byte compressed Uint8Array (0x02/0x03 prefix)
//   - 65-byte uncompressed Uint8Array (0x04 prefix)
//   - 64-byte uncompressed Uint8Array (no prefix, raw x||y)
//   - hex string (with or without 0x) of any of the above
// Returns 33-byte compressed.
export function normalizePubKey(input: Uint8Array | string): Uint8Array {
    let bytes: Uint8Array
    if (typeof input === 'string') {
        bytes = hexToBytes(input)
    } else {
        bytes = input
    }

    if (bytes.length === 33) {
        const point = secp256k1.ProjectivePoint.fromHex(bytes)
        return point.toRawBytes(true)
    }
    if (bytes.length === 65) {
        const point = secp256k1.ProjectivePoint.fromHex(bytes)
        return point.toRawBytes(true)
    }
    if (bytes.length === 64) {
        const withPrefix = new Uint8Array(65)
        withPrefix[0] = 0x04
        withPrefix.set(bytes, 1)
        const point = secp256k1.ProjectivePoint.fromHex(withPrefix)
        return point.toRawBytes(true)
    }
    throw new Error(`invalid pubkey byte length: ${bytes.length}`)
}

// Accepts a 32-byte raw private key or a 32-byte hex string (with or without
// 0x). Returns 32-byte bytes. Rejects invalid scalars.
export function normalizePrivKey(input: Uint8Array | string): Uint8Array {
    let bytes: Uint8Array
    if (typeof input === 'string') {
        bytes = hexToBytes(input)
    } else {
        bytes = input
    }
    if (bytes.length !== 32) {
        throw new Error(`private key must be 32 bytes, got ${bytes.length}`)
    }
    if (!secp256k1.utils.isValidSecretKey(bytes)) {
        throw new Error('invalid secp256k1 private key')
    }
    return bytes
}

function hexToBytes(h: string): Uint8Array {
    const clean = h.startsWith('0x') ? h.slice(2) : h
    if (clean.length % 2 !== 0) {
        throw new Error(`invalid hex string (odd length): ${h}`)
    }
    const out = new Uint8Array(clean.length / 2)
    for (let i = 0; i < out.length; i++) {
        const byte = parseInt(clean.substr(i * 2, 2), 16)
        if (Number.isNaN(byte)) {
            throw new Error(`invalid hex character at offset ${i * 2}`)
        }
        out[i] = byte
    }
    return out
}

// ── ECIES key derivation ───────────────────────────────────────────────────

// Compute the raw 32-byte shared secret x-coordinate via ECDH.
// @noble/curves returns 33-byte compressed (0x02/0x03 || x); we strip the
// prefix so this matches go-ethereum's ecies.GenerateShared, which returns
// just x.
function ecdhSharedX(
    privKey: Uint8Array,
    pubKeyCompressed: Uint8Array
): Uint8Array {
    const shared = secp256k1.getSharedSecret(privKey, pubKeyCompressed, true)
    return shared.slice(1) // drop 0x02/0x03 prefix
}

function deriveAesKey(sharedX: Uint8Array): Uint8Array {
    return hkdf(sha256, sharedX, new Uint8Array(0), ECIES_HKDF_INFO, 32)
}

export function deriveEciesEncryptKey(recipientPub: Uint8Array | string): {
    key: Uint8Array
    ephemeralPub: Uint8Array
} {
    const recipientCompressed = normalizePubKey(recipientPub)

    const ephemeralPriv = secp256k1.utils.randomSecretKey()
    const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true)

    const sharedX = ecdhSharedX(ephemeralPriv, recipientCompressed)
    const key = deriveAesKey(sharedX)

    return { key, ephemeralPub }
}

export function deriveEciesDecryptKey(
    recipientPriv: Uint8Array | string,
    ephemeralPub: Uint8Array
): Uint8Array {
    const priv = normalizePrivKey(recipientPriv)
    const sharedX = ecdhSharedX(priv, ephemeralPub)
    return deriveAesKey(sharedX)
}

// ── Header factories ───────────────────────────────────────────────────────

export function newSymmetricHeader(): EncryptionHeader {
    return new EncryptionHeader(SYMMETRIC_VERSION, randomBytes(16))
}

export function newEciesHeader(recipientPub: Uint8Array | string): {
    header: EncryptionHeader
    key: Uint8Array
} {
    const nonce = randomBytes(16)
    const { key, ephemeralPub } = deriveEciesEncryptKey(recipientPub)
    const header = new EncryptionHeader(ECIES_VERSION, nonce, ephemeralPub)
    return { header, key }
}

// ── Decrypt helpers ────────────────────────────────────────────────────────

// Decrypt a full downloaded file: parses the header, strips it, and decrypts
// the remaining bytes at CTR offset 0. Returns the plaintext.
export function decryptFile(
    key: Uint8Array,
    encrypted: Uint8Array
): Uint8Array {
    const header = parseEncryptionHeader(encrypted)
    const headerSize = header.size()
    const body = new Uint8Array(encrypted.length - headerSize)
    body.set(encrypted.slice(headerSize))
    cryptAt(key, header.nonce, 0, body)
    return body
}

// Decrypt one fragment of a multi-fragment encrypted stream.
//   - isFirstFragment=true: fragment contains the encryption header at the
//     start; strip it, decrypt the remainder starting at CTR offset 0, and
//     return the plaintext plus its length as the new cumulative offset.
//   - isFirstFragment=false: fragment is pure ciphertext; decrypt starting
//     at `dataOffset`, return plaintext and advanced offset.
export function decryptFragmentData(
    key: Uint8Array,
    header: EncryptionHeader,
    fragmentData: Uint8Array,
    isFirstFragment: boolean,
    dataOffset: number
): { plaintext: Uint8Array; newOffset: number } {
    if (isFirstFragment) {
        const headerSize = header.size()
        if (fragmentData.length < headerSize) {
            throw new Error(
                `first fragment too short for encryption header: ${fragmentData.length} bytes`
            )
        }
        const body = new Uint8Array(fragmentData.length - headerSize)
        body.set(fragmentData.slice(headerSize))
        cryptAt(key, header.nonce, 0, body)
        return { plaintext: body, newOffset: body.length }
    }

    const copy = new Uint8Array(fragmentData)
    cryptAt(key, header.nonce, dataOffset, copy)
    return { plaintext: copy, newOffset: dataOffset + copy.length }
}

// Pick the correct AES key for a given header version from the optional
// materials supplied by the caller. Errors cleanly if the required material
// for this version is missing or malformed.
export function resolveDecryptionKey(
    symmetricKey: Uint8Array | undefined,
    privateKey: Uint8Array | string | undefined,
    header: EncryptionHeader
): Uint8Array {
    switch (header.version) {
        case SYMMETRIC_VERSION: {
            if (!symmetricKey || symmetricKey.length === 0) {
                throw new Error(
                    'v1 encrypted file requires a symmetric key (withSymmetricKey)'
                )
            }
            if (symmetricKey.length !== 32) {
                throw new Error(
                    `symmetric key must be 32 bytes, got ${symmetricKey.length}`
                )
            }
            const out = new Uint8Array(32)
            out.set(symmetricKey)
            return out
        }
        case ECIES_VERSION: {
            if (!privateKey) {
                throw new Error(
                    'v2 encrypted file requires a private key (withPrivateKey)'
                )
            }
            return deriveEciesDecryptKey(privateKey, header.ephemeralPub)
        }
        default:
            throw new Error(`unsupported encryption version: ${header.version}`)
    }
}

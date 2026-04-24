import { secp256k1 } from '@noble/curves/secp256k1.js'
import {
    EncryptionHeader,
    parseEncryptionHeader,
    SYMMETRIC_VERSION,
    SYMMETRIC_HEADER_SIZE,
    ECIES_VERSION,
    ECIES_HEADER_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    cryptAt,
    normalizePubKey,
    normalizePrivKey,
    deriveEciesEncryptKey,
    deriveEciesDecryptKey,
    newSymmetricHeader,
    newEciesHeader,
    decryptFile,
    decryptFragmentData,
    resolveDecryptionKey,
} from '../src.ts/common/encryption'

describe('EncryptionHeader v1', () => {
    it('serializes to 17 bytes with version 0x01 and round-trips', () => {
        const nonce = new Uint8Array(16)
        for (let i = 0; i < 16; i++) nonce[i] = i + 1
        const h = new EncryptionHeader(SYMMETRIC_VERSION, nonce)

        const bytes = h.toBytes()
        expect(bytes.length).toBe(SYMMETRIC_HEADER_SIZE)
        expect(bytes.length).toBe(17)
        expect(bytes[0]).toBe(0x01)
        expect(Array.from(bytes.slice(1, 17))).toEqual(Array.from(nonce))

        const parsed = parseEncryptionHeader(bytes)
        expect(parsed.version).toBe(SYMMETRIC_VERSION)
        expect(Array.from(parsed.nonce)).toEqual(Array.from(nonce))
        expect(parsed.size()).toBe(17)
    })

    it('parse rejects too-short data', () => {
        expect(() => parseEncryptionHeader(new Uint8Array([0x01]))).toThrow(
            /too short/i
        )
    })

    it('parse rejects unsupported version', () => {
        const bad = new Uint8Array(17)
        bad[0] = 0xee
        expect(() => parseEncryptionHeader(bad)).toThrow(/unsupported/i)
    })
})

describe('EncryptionHeader v2', () => {
    it('serializes to 50 bytes with version 0x02 and round-trips', () => {
        const nonce = new Uint8Array(16)
        for (let i = 0; i < 16; i++) nonce[i] = 0xa0 + i
        const ephemeralPub = new Uint8Array(EPHEMERAL_PUBKEY_SIZE)
        for (let i = 0; i < EPHEMERAL_PUBKEY_SIZE; i++) ephemeralPub[i] = i

        const h = new EncryptionHeader(ECIES_VERSION, nonce, ephemeralPub)
        const bytes = h.toBytes()

        expect(bytes.length).toBe(ECIES_HEADER_SIZE)
        expect(bytes.length).toBe(50)
        expect(bytes[0]).toBe(0x02)
        expect(Array.from(bytes.slice(1, 1 + EPHEMERAL_PUBKEY_SIZE))).toEqual(
            Array.from(ephemeralPub)
        )
        expect(
            Array.from(
                bytes.slice(
                    1 + EPHEMERAL_PUBKEY_SIZE,
                    1 + EPHEMERAL_PUBKEY_SIZE + 16
                )
            )
        ).toEqual(Array.from(nonce))

        const parsed = parseEncryptionHeader(bytes)
        expect(parsed.version).toBe(ECIES_VERSION)
        expect(Array.from(parsed.ephemeralPub)).toEqual(
            Array.from(ephemeralPub)
        )
        expect(Array.from(parsed.nonce)).toEqual(Array.from(nonce))
        expect(parsed.size()).toBe(50)
    })

    it('parse rejects v2 data shorter than 50 bytes', () => {
        const bad = new Uint8Array(17)
        bad[0] = 0x02
        expect(() => parseEncryptionHeader(bad)).toThrow(/too short/i)
    })
})

describe('cryptAt', () => {
    const key = new Uint8Array(32).fill(0x42)
    const nonce = new Uint8Array(16).fill(0x13)

    it('roundtrips at offset 0 (encrypt then decrypt restores plaintext)', () => {
        const plain = new TextEncoder().encode(
            'hello world encryption test data'
        )
        const buf = new Uint8Array(plain)

        cryptAt(key, nonce, 0, buf)
        expect(Array.from(buf)).not.toEqual(Array.from(plain))

        cryptAt(key, nonce, 0, buf)
        expect(Array.from(buf)).toEqual(Array.from(plain))
    })

    it('encrypting in two halves at offsets 0 and 50 matches a single full-length encrypt', () => {
        const original = new Uint8Array(100)
        for (let i = 0; i < 100; i++) original[i] = i

        const full = new Uint8Array(original)
        cryptAt(key, nonce, 0, full)

        const part1 = original.slice(0, 50)
        const part2 = original.slice(50)
        cryptAt(key, nonce, 0, part1)
        cryptAt(key, nonce, 50, part2)

        expect(Array.from(part1)).toEqual(Array.from(full.slice(0, 50)))
        expect(Array.from(part2)).toEqual(Array.from(full.slice(50)))
    })

    it('decrypting a sub-range of a full ciphertext with the matching offset recovers the original bytes', () => {
        const plain = new Uint8Array(100)
        for (let i = 0; i < 100; i++) plain[i] = i
        const cipher = new Uint8Array(plain)
        cryptAt(key, nonce, 0, cipher)

        const slice = cipher.slice(32)
        cryptAt(key, nonce, 32, slice)

        expect(Array.from(slice)).toEqual(Array.from(plain.slice(32)))
    })

    it('no-ops on empty input', () => {
        const empty = new Uint8Array(0)
        cryptAt(key, nonce, 0, empty)
        expect(empty.length).toBe(0)
    })

    it('handles non-block-aligned offsets (offset not a multiple of 16)', () => {
        const plain = new Uint8Array(64)
        for (let i = 0; i < 64; i++) plain[i] = i * 3
        const cipher = new Uint8Array(plain)
        cryptAt(key, nonce, 0, cipher)

        // Decrypt bytes [7:64] at offset 7 (crosses a block boundary
        // mid-block and exercises the byteSkip path).
        const slice = cipher.slice(7)
        cryptAt(key, nonce, 7, slice)

        expect(Array.from(slice)).toEqual(Array.from(plain.slice(7)))
    })
})

describe('normalizePubKey', () => {
    const priv = new Uint8Array(32).fill(0x01)
    const compressedHex =
        '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'
    const compressedBytes = hexToBytes(compressedHex)

    it('passes 33-byte compressed bytes through', () => {
        const out = normalizePubKey(compressedBytes)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('accepts compressed hex with 0x prefix', () => {
        const out = normalizePubKey('0x' + compressedHex)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('accepts compressed hex without 0x prefix', () => {
        const out = normalizePubKey(compressedHex)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('accepts 65-byte uncompressed bytes and compresses', () => {
        const uncompressed = secp256k1.getPublicKey(priv, false)
        const out = normalizePubKey(uncompressed)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('accepts 64-byte uncompressed-without-prefix bytes', () => {
        const raw = secp256k1.getPublicKey(priv, false).slice(1) // strip 0x04
        const out = normalizePubKey(raw)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('rejects invalid lengths', () => {
        expect(() => normalizePubKey(new Uint8Array(10))).toThrow()
    })
})

describe('normalizePrivKey', () => {
    const hex =
        '0101010101010101010101010101010101010101010101010101010101010101'

    it('passes 32-byte bytes through', () => {
        const out = normalizePrivKey(hexToBytes(hex))
        expect(bytesToHex(out)).toBe(hex)
    })

    it('accepts hex with 0x prefix', () => {
        const out = normalizePrivKey('0x' + hex)
        expect(bytesToHex(out)).toBe(hex)
    })

    it('accepts hex without 0x prefix', () => {
        const out = normalizePrivKey(hex)
        expect(bytesToHex(out)).toBe(hex)
    })

    it('rejects invalid length', () => {
        expect(() => normalizePrivKey(new Uint8Array(10))).toThrow()
        expect(() => normalizePrivKey('beef')).toThrow()
    })

    it('rejects zero/invalid scalar', () => {
        const zero = new Uint8Array(32)
        expect(() => normalizePrivKey(zero)).toThrow(/invalid/)
    })
})

describe('ECIES key derivation', () => {
    it('encrypt key and decrypt key match given the same ephemeral', () => {
        const recipientPriv = secp256k1.utils.randomSecretKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { key: encKey, ephemeralPub } =
            deriveEciesEncryptKey(recipientPub)
        const decKey = deriveEciesDecryptKey(recipientPriv, ephemeralPub)

        expect(encKey.length).toBe(32)
        expect(ephemeralPub.length).toBe(33)
        expect(Array.from(decKey)).toEqual(Array.from(encKey))
    })

    it('generates a fresh ephemeral keypair each call', () => {
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomSecretKey(),
            true
        )
        const { ephemeralPub: a } = deriveEciesEncryptKey(recipientPub)
        const { ephemeralPub: b } = deriveEciesEncryptKey(recipientPub)
        expect(Array.from(a)).not.toEqual(Array.from(b))
    })

    it('wrong private key yields a different AES key', () => {
        const recipientPriv = secp256k1.utils.randomSecretKey()
        const attackerPriv = secp256k1.utils.randomSecretKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { key: right, ephemeralPub } = deriveEciesEncryptKey(recipientPub)
        const wrong = deriveEciesDecryptKey(attackerPriv, ephemeralPub)

        expect(Array.from(wrong)).not.toEqual(Array.from(right))
    })
})

describe('newSymmetricHeader', () => {
    it('creates a v1 header with a fresh 16-byte nonce', () => {
        const a = newSymmetricHeader()
        const b = newSymmetricHeader()
        expect(a.version).toBe(SYMMETRIC_VERSION)
        expect(a.nonce.length).toBe(16)
        expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce))
    })
})

describe('newEciesHeader', () => {
    it('creates a v2 header and returns a matching AES key', () => {
        const recipientPriv = secp256k1.utils.randomSecretKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { header, key } = newEciesHeader(recipientPub)
        expect(header.version).toBe(ECIES_VERSION)
        expect(header.nonce.length).toBe(16)
        expect(header.ephemeralPub.length).toBe(33)
        expect(key.length).toBe(32)

        const decKey = deriveEciesDecryptKey(
            recipientPriv,
            header.ephemeralPub
        )
        expect(Array.from(decKey)).toEqual(Array.from(key))
    })
})

describe('decryptFile', () => {
    it('strips the header and decrypts the remainder (v1)', () => {
        const key = new Uint8Array(32).fill(0x42)
        const header = newSymmetricHeader()
        const plain = new TextEncoder().encode('test data for encryption')

        const cipherBody = new Uint8Array(plain)
        cryptAt(key, header.nonce, 0, cipherBody)

        const file = new Uint8Array(SYMMETRIC_HEADER_SIZE + cipherBody.length)
        file.set(header.toBytes(), 0)
        file.set(cipherBody, SYMMETRIC_HEADER_SIZE)

        const dec = decryptFile(key, file)
        expect(Array.from(dec)).toEqual(Array.from(plain))
    })

    it('strips the header and decrypts the remainder (v2)', () => {
        const recipientPriv = secp256k1.utils.randomSecretKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)
        const { header, key } = newEciesHeader(recipientPub)
        const plain = new Uint8Array(200)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 11) & 0xff

        const cipherBody = new Uint8Array(plain)
        cryptAt(key, header.nonce, 0, cipherBody)

        const file = new Uint8Array(ECIES_HEADER_SIZE + cipherBody.length)
        file.set(header.toBytes(), 0)
        file.set(cipherBody, ECIES_HEADER_SIZE)

        const resolved = deriveEciesDecryptKey(
            recipientPriv,
            header.ephemeralPub
        )
        const dec = decryptFile(resolved, file)
        expect(Array.from(dec)).toEqual(Array.from(plain))
    })

    it('rejects too-short data', () => {
        const key = new Uint8Array(32)
        expect(() => decryptFile(key, new Uint8Array([0x01, 0x02]))).toThrow(
            /too short/i
        )
    })

    it('rejects wrong version byte', () => {
        const key = new Uint8Array(32)
        const data = new Uint8Array(SYMMETRIC_HEADER_SIZE + 1)
        data[0] = 0xff
        expect(() => decryptFile(key, data)).toThrow(/unsupported/i)
    })
})

describe('decryptFragmentData', () => {
    it('round-trips across two fragments (v1)', () => {
        const key = new Uint8Array(32).fill(0x42)
        const header = newSymmetricHeader()
        const plain = new Uint8Array(150)
        for (let i = 0; i < 150; i++) plain[i] = i

        const cipherBody = new Uint8Array(plain)
        cryptAt(key, header.nonce, 0, cipherBody)
        const fullStream = new Uint8Array(
            SYMMETRIC_HEADER_SIZE + cipherBody.length
        )
        fullStream.set(header.toBytes(), 0)
        fullStream.set(cipherBody, SYMMETRIC_HEADER_SIZE)

        const frag0 = fullStream.slice(0, 100)
        const frag1 = fullStream.slice(100)

        const { plaintext: p0, newOffset: off0 } = decryptFragmentData(
            key,
            header,
            frag0,
            true,
            0
        )
        expect(off0).toBe(100 - SYMMETRIC_HEADER_SIZE)
        expect(Array.from(p0)).toEqual(Array.from(plain.slice(0, 83)))

        const { plaintext: p1, newOffset: off1 } = decryptFragmentData(
            key,
            header,
            frag1,
            false,
            off0
        )
        expect(off1).toBe(150)
        expect(Array.from(p1)).toEqual(Array.from(plain.slice(83)))
    })

    it('rejects first-fragment data shorter than header', () => {
        const key = new Uint8Array(32)
        const header = new EncryptionHeader(
            SYMMETRIC_VERSION,
            new Uint8Array(16)
        )
        expect(() =>
            decryptFragmentData(key, header, new Uint8Array([0x01]), true, 0)
        ).toThrow(/first fragment too short/i)
    })
})

describe('resolveDecryptionKey', () => {
    it('returns symmetric key bytes for v1 header', () => {
        const sym = new Uint8Array(32).fill(0x7)
        const hdr = new EncryptionHeader(
            SYMMETRIC_VERSION,
            new Uint8Array(16)
        )
        const key = resolveDecryptionKey(sym, undefined, hdr)
        expect(Array.from(key)).toEqual(Array.from(sym))
    })

    it('derives key from privkey for v2 header', () => {
        const recipientPriv = secp256k1.utils.randomSecretKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)
        const { header, key: encKey } = newEciesHeader(recipientPub)

        const resolved = resolveDecryptionKey(
            undefined,
            recipientPriv,
            header
        )
        expect(Array.from(resolved)).toEqual(Array.from(encKey))
    })

    it('errors if v1 header but no symmetric key', () => {
        const hdr = new EncryptionHeader(
            SYMMETRIC_VERSION,
            new Uint8Array(16)
        )
        expect(() =>
            resolveDecryptionKey(undefined, undefined, hdr)
        ).toThrow(/symmetric/i)
    })

    it('errors if v2 header but no private key', () => {
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomSecretKey(),
            true
        )
        const { header } = newEciesHeader(recipientPub)
        expect(() =>
            resolveDecryptionKey(undefined, undefined, header)
        ).toThrow(/private key/i)
    })

    it('errors if v1 symmetric key length is wrong', () => {
        const hdr = new EncryptionHeader(
            SYMMETRIC_VERSION,
            new Uint8Array(16)
        )
        expect(() =>
            resolveDecryptionKey(new Uint8Array(31), undefined, hdr)
        ).toThrow(/32 bytes/)
    })
})

function hexToBytes(h: string): Uint8Array {
    const clean = h.startsWith('0x') ? h.slice(2) : h
    const out = new Uint8Array(clean.length / 2)
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16)
    }
    return out
}

function bytesToHex(b: Uint8Array): string {
    return Array.from(b)
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('')
}

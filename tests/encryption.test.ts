import {
    EncryptionHeader,
    parseEncryptionHeader,
    SYMMETRIC_VERSION,
    SYMMETRIC_HEADER_SIZE,
    ECIES_VERSION,
    ECIES_HEADER_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
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

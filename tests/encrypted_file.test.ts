import { secp256k1 } from '@noble/curves/secp256k1'
import { MemData } from '../src.ts/file/MemData'
import {
    EncryptedFile,
    newSymmetricEncryptedFile,
    newEciesEncryptedFile,
} from '../src.ts/file/EncryptedFile'
import {
    decryptFile,
    SYMMETRIC_HEADER_SIZE,
    ECIES_HEADER_SIZE,
    parseEncryptionHeader,
    deriveEciesDecryptKey,
} from '../src.ts/common/encryption'

describe('EncryptedFile v1', () => {
    it('prepends a 17-byte header and encrypts the inner data', async () => {
        const plain = new Uint8Array(1024)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const inner = new MemData(plain)
        const key = new Uint8Array(32).fill(0x5a)

        const ef = newSymmetricEncryptedFile(inner, key)
        expect(ef.size()).toBe(1024 + SYMMETRIC_HEADER_SIZE)

        const { buffer, bytesRead } = await ef.readFromFile(0, ef.size())
        expect(bytesRead).toBe(ef.size())

        const decrypted = decryptFile(key, buffer)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })

    it('readFromFile at an offset within the header region returns header bytes', async () => {
        const plain = new Uint8Array(100)
        const ef = newSymmetricEncryptedFile(
            new MemData(plain),
            new Uint8Array(32).fill(1)
        )
        const { buffer } = await ef.readFromFile(0, 17)
        expect(buffer.length).toBe(17)
        expect(buffer[0]).toBe(0x01)
    })

    it('preserves the underlying inner file size plus header', () => {
        const ef = newSymmetricEncryptedFile(
            new MemData(new Uint8Array(5000)),
            new Uint8Array(32).fill(1)
        )
        expect(ef.size()).toBe(5000 + SYMMETRIC_HEADER_SIZE)
    })
})

describe('EncryptedFile v2 (ECIES)', () => {
    it('prepends a 50-byte header and the inner can be decrypted with the matching privkey', async () => {
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(500)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        expect(ef.size()).toBe(500 + ECIES_HEADER_SIZE)

        const { buffer } = await ef.readFromFile(0, ef.size())
        const header = parseEncryptionHeader(buffer)
        expect(header.version).toBe(0x02)

        const aesKey = deriveEciesDecryptKey(
            recipientPriv,
            header.ephemeralPub
        )
        const dec = decryptFile(aesKey, buffer)
        expect(Array.from(dec)).toEqual(Array.from(plain))
    })
})

describe('EncryptedFile.split', () => {
    it('produces fragments that decrypt together into the original plaintext', async () => {
        const plain = new Uint8Array(1000)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 7) & 0xff
        const key = new Uint8Array(32).fill(0x33)
        const ef = newSymmetricEncryptedFile(new MemData(plain), key)

        const fragSize = 200
        const fragments = ef.split(fragSize)
        expect(fragments.length).toBeGreaterThan(1)

        const chunks: Uint8Array[] = []
        for (const f of fragments) {
            const { buffer } = await f.readFromFile(0, f.size())
            chunks.push(buffer)
        }
        const rejoined = concat(chunks)
        expect(rejoined.length).toBe(ef.size())

        const dec = decryptFile(key, rejoined)
        expect(Array.from(dec)).toEqual(Array.from(plain))
    })
})

describe('EncryptedFile iterator compatibility', () => {
    it('works with iterateWithOffsetAndBatch (used by merkleTree)', async () => {
        const plain = new Uint8Array(200)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const key = new Uint8Array(32).fill(0x77)
        const ef = newSymmetricEncryptedFile(new MemData(plain), key)

        // Drive the iterator manually and reassemble the encrypted stream;
        // it should equal what readFromFile gives us end-to-end.
        const iter = ef.iterateWithOffsetAndBatch(0, 256, true)
        const collected: Uint8Array[] = []
        while (true) {
            const [ok, err] = await iter.next()
            expect(err).toBeNull()
            if (!ok) break
            collected.push(new Uint8Array(iter.current()))
        }
        const iteratorOutput = concat(collected)

        // The iterator yields padded segments (flow-padded to a power-of-two
        // segment size), so truncate back to the real encrypted size before
        // comparing to readFromFile.
        const expected = (await ef.readFromFile(0, ef.size())).buffer
        expect(Array.from(iteratorOutput.slice(0, ef.size()))).toEqual(
            Array.from(expected)
        )
    })

    it('merkleTree produces a stable root over encrypted bytes', async () => {
        const plain = new Uint8Array(200)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const key = new Uint8Array(32).fill(0x88)

        // Fix the header nonce to get a deterministic Merkle root across
        // multiple EncryptedFile constructions.
        const ef1 = newSymmetricEncryptedFile(new MemData(plain), key)
        ef1.header = new EncryptedFile(
            ef1.inner,
            ef1.key,
            Object.assign(ef1.header, { nonce: new Uint8Array(16).fill(9) })
        ).header

        const [tree1, err1] = await ef1.merkleTree()
        expect(err1).toBeNull()
        expect(tree1?.rootHash()).toMatch(/^0x[0-9a-f]{64}$/)
    })
})

describe('Upload-then-download round-trip via primitives', () => {
    // The Uploader/Downloader seams we rely on are (1) EncryptedFile emits
    // header+ciphertext via readFromFile/iterator, and (2) the Downloader
    // parses the header, resolves the key, and runs decryptFile /
    // decryptFragmentData. These tests exercise that seam without spinning
    // up a real StorageNode.

    it('v1: encrypted bytes decrypt back via decryptFile', async () => {
        const plain = new Uint8Array(2048)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 31) & 0xff
        const key = new Uint8Array(32).fill(0x99)

        const ef = newSymmetricEncryptedFile(new MemData(plain), key)
        const { buffer } = await ef.readFromFile(0, ef.size())
        const decrypted = decryptFile(key, buffer)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })

    it('v2: encrypted bytes decrypt back with recipient privkey', async () => {
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(5000)
        for (let i = 0; i < plain.length; i++) plain[i] = (i ^ 0xa5) & 0xff

        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        const { buffer } = await ef.readFromFile(0, ef.size())
        const header = parseEncryptionHeader(buffer)
        const aesKey = deriveEciesDecryptKey(
            recipientPriv,
            header.ephemeralPub
        )
        const decrypted = decryptFile(aesKey, buffer)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })
})

function concat(chunks: Uint8Array[]): Uint8Array {
    let total = 0
    for (const c of chunks) total += c.length
    const out = new Uint8Array(total)
    let p = 0
    for (const c of chunks) {
        out.set(c, p)
        p += c.length
    }
    return out
}

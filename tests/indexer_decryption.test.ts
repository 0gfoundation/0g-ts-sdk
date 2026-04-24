import { secp256k1 } from '@noble/curves/secp256k1'
import {
    tryDecrypt,
    tryDecryptFragments,
} from '../src.ts/indexer/decryption'
import { MemData } from '../src.ts/file/MemData'
import {
    newSymmetricEncryptedFile,
    newEciesEncryptedFile,
} from '../src.ts/file/EncryptedFile'

describe('tryDecrypt (Indexer best-effort)', () => {
    it('returns plaintext + decrypted=true for a v1-encrypted blob with matching symmetric key', async () => {
        const plain = new Uint8Array(200)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const key = new Uint8Array(32).fill(0x33)

        const ef = newSymmetricEncryptedFile(new MemData(plain), key)
        const { buffer: encrypted } = await ef.readFromFile(0, ef.size())

        const out = tryDecrypt(encrypted, { symmetricKey: key })
        expect(out.decrypted).toBe(true)
        expect(Array.from(out.bytes)).toEqual(Array.from(plain))
    })

    it('returns plaintext + decrypted=true for a v2-encrypted blob with matching private key', async () => {
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(1000)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 3) & 0xff

        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        const { buffer: encrypted } = await ef.readFromFile(0, ef.size())

        const out = tryDecrypt(encrypted, { privateKey: recipientPriv })
        expect(out.decrypted).toBe(true)
        expect(Array.from(out.bytes)).toEqual(Array.from(plain))
    })

    it('falls back to raw (decrypted=false) when the file is not encrypted', () => {
        const plain = new Uint8Array([0x41, 0x42, 0x43, 0x44]) // "ABCD"
        const out = tryDecrypt(plain, {
            symmetricKey: new Uint8Array(32).fill(0x99),
        })
        expect(out.decrypted).toBe(false)
        expect(Array.from(out.bytes)).toEqual(Array.from(plain))
    })

    it('falls back to raw when header version is v1 but caller only supplied a private key', async () => {
        const plain = new Uint8Array(100)
        const key = new Uint8Array(32).fill(0x11)
        const ef = newSymmetricEncryptedFile(new MemData(plain), key)
        const { buffer: encrypted } = await ef.readFromFile(0, ef.size())

        const out = tryDecrypt(encrypted, {
            privateKey: secp256k1.utils.randomPrivateKey(),
        })
        expect(out.decrypted).toBe(false)
        expect(Array.from(out.bytes)).toEqual(Array.from(encrypted))
    })

    it('falls back to raw when header version is v2 but caller only supplied a symmetric key', async () => {
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomPrivateKey(),
            true
        )
        const ef = newEciesEncryptedFile(new MemData(new Uint8Array(100)), recipientPub)
        const { buffer: encrypted } = await ef.readFromFile(0, ef.size())

        const out = tryDecrypt(encrypted, {
            symmetricKey: new Uint8Array(32),
        })
        expect(out.decrypted).toBe(false)
        expect(Array.from(out.bytes)).toEqual(Array.from(encrypted))
    })

    it('falls back to raw when v2 ephemeral pubkey is not a valid curve point', () => {
        // Construct a fake v2-looking blob whose "ephemeral pubkey" bytes are
        // garbage (not on the secp256k1 curve). This is the defensive check:
        // a plain file that happens to start with 0x02 should not be
        // mis-decrypted into random bytes.
        const fake = new Uint8Array(60)
        fake[0] = 0x02 // v2 version byte
        // bytes 1..34: "ephemeral pubkey" — all zeros (not a valid point)
        // bytes 34..50: "nonce" — arbitrary
        // rest: "ciphertext"
        const priv = secp256k1.utils.randomPrivateKey()
        const out = tryDecrypt(fake, { privateKey: priv })
        expect(out.decrypted).toBe(false)
        expect(Array.from(out.bytes)).toEqual(Array.from(fake))
    })

    it('returns raw for an empty blob', () => {
        const out = tryDecrypt(new Uint8Array(0), {
            symmetricKey: new Uint8Array(32),
        })
        expect(out.decrypted).toBe(false)
        expect(out.bytes.length).toBe(0)
    })

    it('returns raw for a 1-byte blob that starts with a valid-looking version', () => {
        const out = tryDecrypt(new Uint8Array([0x01]), {
            symmetricKey: new Uint8Array(32),
        })
        expect(out.decrypted).toBe(false)
        expect(Array.from(out.bytes)).toEqual([0x01])
    })

    it('tryDecryptFragments: decrypts multi-fragment v1 stream matching Go indexer flow', async () => {
        // Build a v1-encrypted stream larger than one fragment, slice it into
        // three contiguous fragments, and confirm tryDecryptFragments restores
        // the original plaintext across fragments with CTR-offset tracking.
        const plain = new Uint8Array(900)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 5) & 0xff
        const key = new Uint8Array(32).fill(0x55)

        const ef = newSymmetricEncryptedFile(new MemData(plain), key)
        const { buffer: stream } = await ef.readFromFile(0, ef.size())

        const frag0 = stream.slice(0, 300)
        const frag1 = stream.slice(300, 600)
        const frag2 = stream.slice(600)

        const plaintexts = tryDecryptFragments(
            [frag0, frag1, frag2],
            key,
            undefined
        )
        expect(plaintexts).not.toBeNull()
        const joined = concatBytes(plaintexts!)
        expect(Array.from(joined)).toEqual(Array.from(plain))
    })

    it('tryDecryptFragments: decrypts multi-fragment v2 stream with private key', async () => {
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(2000)
        for (let i = 0; i < plain.length; i++) plain[i] = (i ^ 0xa5) & 0xff

        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        const { buffer: stream } = await ef.readFromFile(0, ef.size())

        // Uneven fragment boundaries exercise the byte-level offset path
        // inside cryptAt (fragment boundaries not 16-aligned).
        const frag0 = stream.slice(0, 733)
        const frag1 = stream.slice(733, 1500)
        const frag2 = stream.slice(1500)

        const plaintexts = tryDecryptFragments(
            [frag0, frag1, frag2],
            undefined,
            recipientPriv
        )
        expect(plaintexts).not.toBeNull()
        expect(Array.from(concatBytes(plaintexts!))).toEqual(Array.from(plain))
    })

    it('tryDecryptFragments: returns null (fallback) when fragment 0 is not an encryption header', () => {
        const result = tryDecryptFragments(
            [new Uint8Array([0x41, 0x42, 0x43])],
            new Uint8Array(32),
            undefined
        )
        expect(result).toBeNull()
    })

    it('tryDecryptFragments: returns null when caller supplied wrong key type', async () => {
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomPrivateKey(),
            true
        )
        const ef = newEciesEncryptedFile(
            new MemData(new Uint8Array(200)),
            recipientPub
        )
        const { buffer: stream } = await ef.readFromFile(0, ef.size())

        // Caller has only a symmetric key but file is v2 → null.
        const out = tryDecryptFragments(
            [stream],
            new Uint8Array(32).fill(1),
            undefined
        )
        expect(out).toBeNull()
    })

    it('accepts private key as hex string', async () => {
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)
        const privHex =
            '0x' +
            Array.from(recipientPriv)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')

        const ef = newEciesEncryptedFile(
            new MemData(new Uint8Array(64)),
            recipientPub
        )
        const { buffer: encrypted } = await ef.readFromFile(0, ef.size())

        const out = tryDecrypt(encrypted, { privateKey: privHex })
        expect(out.decrypted).toBe(true)
    })
})

function concatBytes(chunks: Uint8Array[]): Uint8Array {
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

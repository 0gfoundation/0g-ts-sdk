# ts-sdk v1 + v2 (ECIES) encryption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add wire-compatible v1 (symmetric AES-256-CTR) and v2 (ECIES over secp256k1 + HKDF-SHA256 + AES-256-CTR) encryption to the 0G ts-sdk so the frontend can encrypt to a recipient's secp256k1 public key and decrypt with the matching private key (wallet self-encryption).

**Architecture:** One primitives module (`src.ts/common/encryption.ts`) hosts the crypto. One file wrapper (`src.ts/file/EncryptedFile.ts`) wraps any `AbstractFile` and produces header-prefixed encrypted bytes on read, so the existing Merkle-tree, segment-upload, and fragment pipelines just work with encrypted data transparently. `Uploader` gets a single `encryption` option (discriminated union). `Downloader` gets two fluent setters (`withSymmetricKey`, `withPrivateKey`) plus a post-download decrypt pass.

**Tech Stack:** TypeScript, Jest (ts-jest preset), `@noble/curves/secp256k1` (ECDH), `@noble/hashes/hkdf` + `sha256` (HKDF-SHA256), `@noble/ciphers/aes` (`ctr`), ethers 6 (peer dep, unchanged).

**Spec:** [docs/superpowers/specs/2026-04-23-ts-sdk-ecies-encryption-design.md](../specs/2026-04-23-ts-sdk-ecies-encryption-design.md)

**Acceptance criterion:** `pnpm test` passes.

---

## File map

**New:**
- `src.ts/common/encryption.ts` — primitives
- `src.ts/file/EncryptedFile.ts` — `EncryptedFile` + `EncryptedFileFragment`
- `tests/encryption.test.ts` — primitive unit tests
- `tests/encrypted_file.test.ts` — file-wrapper integration tests

**Modified:**
- `package.json` — add three `@noble/*` deps
- `src.ts/common/index.ts` — re-export encryption primitives
- `src.ts/file/index.ts` — re-export `EncryptedFile`
- `src.ts/transfer/types.ts` — extend `UploadOption`
- `src.ts/transfer/Uploader.ts` — wrap data pre-Merkle when `encryption` is set
- `src.ts/transfer/Downloader.ts` — key setters + decrypt flow
- `src.ts/index.ts` — re-export public entry points

---

## Task 1: Add noble deps

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install runtime deps**

Run:
```bash
pnpm add @noble/curves @noble/hashes @noble/ciphers
```
Expected: `package.json` gains `"@noble/curves"`, `"@noble/hashes"`, `"@noble/ciphers"` under `dependencies`; `pnpm-lock.yaml` updates.

- [ ] **Step 2: Verify the package can still build**

Run:
```bash
pnpm run build-esm
```
Expected: exit 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add @noble/curves, @noble/hashes, @noble/ciphers deps"
```

---

## Task 2: Encryption header — v1 parse/serialize

**Files:**
- Create: `src.ts/common/encryption.ts`
- Create: `tests/encryption.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tests/encryption.test.ts`:

```ts
import {
    EncryptionHeader,
    parseEncryptionHeader,
    SYMMETRIC_VERSION,
    SYMMETRIC_HEADER_SIZE,
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
```

- [ ] **Step 2: Run the test, expect failure**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "EncryptionHeader v1"
```
Expected: FAIL with "Cannot find module '../src.ts/common/encryption'".

- [ ] **Step 3: Create the encryption module with v1 header**

Create `src.ts/common/encryption.ts`:

```ts
// Wire-compatible with 0g-storage-client commit 6d39443.
// v1: [version=0x01][nonce:16]            — 17 bytes
// v2: [version=0x02][ephemeralPub:33][nonce:16] — 50 bytes

export const SYMMETRIC_VERSION = 1
export const ECIES_VERSION = 2
export const SYMMETRIC_HEADER_SIZE = 17
export const EPHEMERAL_PUBKEY_SIZE = 33
export const ECIES_HEADER_SIZE = 1 + EPHEMERAL_PUBKEY_SIZE + 16

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
```

- [ ] **Step 4: Run the test, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "EncryptionHeader v1"
```
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add v1 (symmetric) header parse/serialize"
```

---

## Task 3: v2 header parse/serialize

**Files:**
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Append v2 tests**

Append to `tests/encryption.test.ts`:

```ts
import {
    ECIES_VERSION,
    ECIES_HEADER_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
} from '../src.ts/common/encryption'

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
                bytes.slice(1 + EPHEMERAL_PUBKEY_SIZE, 1 + EPHEMERAL_PUBKEY_SIZE + 16)
            )
        ).toEqual(Array.from(nonce))

        const parsed = parseEncryptionHeader(bytes)
        expect(parsed.version).toBe(ECIES_VERSION)
        expect(Array.from(parsed.ephemeralPub)).toEqual(Array.from(ephemeralPub))
        expect(Array.from(parsed.nonce)).toEqual(Array.from(nonce))
        expect(parsed.size()).toBe(50)
    })

    it('parse rejects v2 data shorter than 50 bytes', () => {
        const bad = new Uint8Array(17)
        bad[0] = 0x02
        expect(() => parseEncryptionHeader(bad)).toThrow(/too short/i)
    })
})
```

- [ ] **Step 2: Run the suite, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "EncryptionHeader v2"
```
Expected: PASS (2 tests). The v2 branch in `parseEncryptionHeader` already exists from Task 2.

- [ ] **Step 3: Commit**

```bash
git add tests/encryption.test.ts
git commit -m "test(encryption): cover v2 header roundtrip"
```

---

## Task 4: cryptAt — AES-256-CTR with byte-level offset

**Files:**
- Modify: `src.ts/common/encryption.ts`
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Write the failing tests**

Append to `tests/encryption.test.ts`:

```ts
import { cryptAt } from '../src.ts/common/encryption'

describe('cryptAt', () => {
    const key = new Uint8Array(32).fill(0x42)
    const nonce = new Uint8Array(16).fill(0x13)

    it('roundtrips at offset 0 (encrypt then decrypt restores plaintext)', () => {
        const plain = new TextEncoder().encode('hello world encryption test data')
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
})
```

- [ ] **Step 2: Run the tests, expect failure**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "cryptAt"
```
Expected: FAIL with "cryptAt is not a function" or module-level import error.

- [ ] **Step 3: Implement cryptAt in `src.ts/common/encryption.ts`**

Append to `src.ts/common/encryption.ts`:

```ts
import { ctr } from '@noble/ciphers/aes'

// cryptAt encrypts or decrypts data in-place at plaintext byte offset `offset`.
// AES-256-CTR is symmetric — encrypt and decrypt are the same XOR operation.
// counter = nonce + floor(offset/16) big-endian; byteSkip = offset mod 16 bytes
// of keystream are discarded before the XOR, so fragment-offset decryption
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

    const cipher = ctr(key, counter)

    if (byteOffset > 0) {
        const skip = new Uint8Array(byteOffset)
        cipher.encrypt(skip) // consume keystream
    }

    const out = cipher.encrypt(data)
    data.set(out)
}

// Big-endian 128-bit add of `val` into the 16-byte counter (in place).
// val is a non-negative JS number (safe up to 2^53 blocks ≈ 144 PB of ciphertext,
// which is beyond any realistic file size).
function addToCounter(counter: Uint8Array, val: number): void {
    let carry = val
    for (let i = 15; i >= 0 && carry > 0; i--) {
        const sum = counter[i] + (carry & 0xff)
        counter[i] = sum & 0xff
        carry = (carry >>> 8) + (sum >>> 8)
    }
}
```

- [ ] **Step 4: Run the tests, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "cryptAt"
```
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add cryptAt (AES-256-CTR with byte-level offset)"
```

---

## Task 5: Key normalization helpers

**Files:**
- Modify: `src.ts/common/encryption.ts`
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Write failing tests**

Append to `tests/encryption.test.ts`:

```ts
import { normalizePubKey, normalizePrivKey } from '../src.ts/common/encryption'

describe('normalizePubKey', () => {
    // Valid secp256k1 pubkey derived from private key 0x01...01
    const compressedHex =
        '021b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'
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
        // Uncompressed form of the same key: 0x04 || x || y
        const uncompressedHex =
            '041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f' +
            '53b9e7b9fc66346ac830d9e0edb94dd0b0ef1e37c8f3c7cf0c3d6c5c7e9fbb9ad'
        // Note: y-coord above is illustrative; recompute below via curve math in test vector.
        // For this plan we recompute via @noble/curves if needed.
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const priv = hexToBytes(
            '0101010101010101010101010101010101010101010101010101010101010101'
        )
        const uncompressed = secp256k1.getPublicKey(priv, false) // 65 bytes
        const out = normalizePubKey(uncompressed)
        expect(bytesToHex(out)).toBe(compressedHex)
    })

    it('rejects 64-byte uncompressed without prefix by attempting with 0x04 prefix', () => {
        // We accept hex of uncompressed with or without leading 04.
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const priv = hexToBytes(
            '0101010101010101010101010101010101010101010101010101010101010101'
        )
        const uncompressed = secp256k1.getPublicKey(priv, false).slice(1) // strip 0x04, 64 bytes
        const out = normalizePubKey(uncompressed)
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
})

// local helpers used by the two describe blocks
function hexToBytes(h: string): Uint8Array {
    const clean = h.startsWith('0x') ? h.slice(2) : h
    if (clean.length % 2 !== 0) throw new Error('odd hex')
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
```

The `021b84c5...` compressed hex is derived from private key `0x01...01` via secp256k1; the implementation uses `@noble/curves` for real derivation, so the test recomputes it rather than hardcoding a mismatch risk — only the assertion in the first three `normalizePubKey` tests uses the hardcoded value. If that value disagrees with what noble computes, adjust the hardcoded value to match `secp256k1.getPublicKey(privOfOnes, true)` and re-run.

- [ ] **Step 2: Implement normalizers in `src.ts/common/encryption.ts`**

Append to `src.ts/common/encryption.ts`:

```ts
import { secp256k1 } from '@noble/curves/secp256k1'

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
        // Already compressed — validate by decoding and re-encoding via noble.
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

// Accepts a 32-byte raw private key or a 32-byte hex string (with or without 0x).
// Returns 32-byte bytes. Rejects invalid scalars.
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
    if (!secp256k1.utils.isValidPrivateKey(bytes)) {
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
```

- [ ] **Step 3: Run the tests, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "normalize"
```
Expected: PASS. If the first three `normalizePubKey` tests fail because the hardcoded `compressedHex` disagrees with noble's derivation from priv=0x01...01, print the real value:

```bash
node -e 'console.log(Buffer.from(require("@noble/curves/secp256k1").secp256k1.getPublicKey(Buffer.from("0101010101010101010101010101010101010101010101010101010101010101","hex"),true)).toString("hex"))'
```

and update the test's `compressedHex` constant to that value, then re-run.

- [ ] **Step 4: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add normalizePubKey / normalizePrivKey"
```

---

## Task 6: ECIES key derivation

**Files:**
- Modify: `src.ts/common/encryption.ts`
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Write failing tests**

Append to `tests/encryption.test.ts`:

```ts
import {
    deriveEciesEncryptKey,
    deriveEciesDecryptKey,
} from '../src.ts/common/encryption'

describe('ECIES key derivation', () => {
    it('encrypt key and decrypt key match given the same ephemeral', () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { key: encKey, ephemeralPub } =
            deriveEciesEncryptKey(recipientPub)
        const decKey = deriveEciesDecryptKey(recipientPriv, ephemeralPub)

        expect(encKey.length).toBe(32)
        expect(ephemeralPub.length).toBe(33)
        expect(Array.from(decKey)).toEqual(Array.from(encKey))
    })

    it('generates a fresh ephemeral keypair each call', () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomPrivateKey(),
            true
        )
        const { ephemeralPub: a } = deriveEciesEncryptKey(recipientPub)
        const { ephemeralPub: b } = deriveEciesEncryptKey(recipientPub)
        expect(Array.from(a)).not.toEqual(Array.from(b))
    })

    it('wrong private key yields a different AES key', () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const attackerPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { key: right, ephemeralPub } = deriveEciesEncryptKey(recipientPub)
        const wrong = deriveEciesDecryptKey(attackerPriv, ephemeralPub)

        expect(Array.from(wrong)).not.toEqual(Array.from(right))
    })
})
```

- [ ] **Step 2: Run the tests, expect failure**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "ECIES key derivation"
```
Expected: FAIL (functions not exported).

- [ ] **Step 3: Implement derivation**

Append to `src.ts/common/encryption.ts`:

```ts
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'

// Domain-separation string. MUST match the Go client byte-for-byte for interop:
// `var eciesHKDFInfo = []byte("0g-storage-client/ecies/v1/aes-256")`
const ECIES_HKDF_INFO = new TextEncoder().encode(
    '0g-storage-client/ecies/v1/aes-256'
)

// Compute the raw 32-byte shared secret x-coordinate via ECDH.
// @noble/curves returns 33-byte compressed (0x02/0x03 || x); we strip the prefix
// so this matches go-ethereum's ecies.GenerateShared, which returns just x.
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

export function deriveEciesEncryptKey(
    recipientPub: Uint8Array | string
): { key: Uint8Array; ephemeralPub: Uint8Array } {
    const recipientCompressed = normalizePubKey(recipientPub)

    const ephemeralPriv = secp256k1.utils.randomPrivateKey()
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
```

- [ ] **Step 4: Run the tests, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "ECIES key derivation"
```
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add ECIES key derivation (secp256k1 ECDH + HKDF-SHA256)"
```

---

## Task 7: newSymmetricHeader / newEciesHeader + decryptFile

**Files:**
- Modify: `src.ts/common/encryption.ts`
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Write failing tests**

Append to `tests/encryption.test.ts`:

```ts
import {
    newSymmetricHeader,
    newEciesHeader,
    decryptFile,
} from '../src.ts/common/encryption'

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
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const { header, key } = newEciesHeader(recipientPub)
        expect(header.version).toBe(ECIES_VERSION)
        expect(header.nonce.length).toBe(16)
        expect(header.ephemeralPub.length).toBe(33)
        expect(key.length).toBe(32)

        // The returned key must equal the one derived from recipientPriv + header.ephemeralPub
        const decKey = deriveEciesDecryptKey(recipientPriv, header.ephemeralPub)
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
```

- [ ] **Step 2: Run the tests, expect failure**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "newSymmetricHeader|newEciesHeader|decryptFile"
```
Expected: FAIL (new functions not exported).

- [ ] **Step 3: Implement the three functions**

Append to `src.ts/common/encryption.ts`:

```ts
import { randomBytes } from '@noble/hashes/utils'

export function newSymmetricHeader(): EncryptionHeader {
    return new EncryptionHeader(SYMMETRIC_VERSION, randomBytes(16))
}

export function newEciesHeader(
    recipientPub: Uint8Array | string
): { header: EncryptionHeader; key: Uint8Array } {
    const nonce = randomBytes(16)
    const { key, ephemeralPub } = deriveEciesEncryptKey(recipientPub)
    const header = new EncryptionHeader(ECIES_VERSION, nonce, ephemeralPub)
    return { header, key }
}

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
```

- [ ] **Step 4: Run the tests, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts
```
Expected: PASS (all primitive suites).

- [ ] **Step 5: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add header factories and decryptFile"
```

---

## Task 8: decryptFragmentData + resolveDecryptionKey

**Files:**
- Modify: `src.ts/common/encryption.ts`
- Modify: `tests/encryption.test.ts`

- [ ] **Step 1: Write failing tests**

Append to `tests/encryption.test.ts`:

```ts
import {
    decryptFragmentData,
    resolveDecryptionKey,
} from '../src.ts/common/encryption'

describe('decryptFragmentData', () => {
    it('round-trips across two fragments (v1)', () => {
        const key = new Uint8Array(32).fill(0x42)
        const header = newSymmetricHeader()
        const plain = new Uint8Array(150)
        for (let i = 0; i < 150; i++) plain[i] = i

        // Encrypted stream: [17-byte header][150 bytes cipher]
        const cipherBody = new Uint8Array(plain)
        cryptAt(key, header.nonce, 0, cipherBody)
        const fullStream = new Uint8Array(
            SYMMETRIC_HEADER_SIZE + cipherBody.length
        )
        fullStream.set(header.toBytes(), 0)
        fullStream.set(cipherBody, SYMMETRIC_HEADER_SIZE)

        // Split into two fragments at byte 100 (arbitrary)
        const frag0 = fullStream.slice(0, 100) // contains header (17 bytes) + 83 bytes of cipher
        const frag1 = fullStream.slice(100) // 67 bytes of pure cipher

        const { plaintext: p0, newOffset: off0 } = decryptFragmentData(
            key,
            header,
            frag0,
            true,
            0
        )
        expect(off0).toBe(100 - SYMMETRIC_HEADER_SIZE) // 83
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
        const header = new EncryptionHeader(SYMMETRIC_VERSION, new Uint8Array(16))
        expect(() =>
            decryptFragmentData(key, header, new Uint8Array([0x01]), true, 0)
        ).toThrow(/first fragment too short/i)
    })
})

describe('resolveDecryptionKey', () => {
    it('returns symmetric key bytes for v1 header', () => {
        const sym = new Uint8Array(32).fill(0x7)
        const hdr = new EncryptionHeader(SYMMETRIC_VERSION, new Uint8Array(16))
        const key = resolveDecryptionKey(sym, undefined, hdr)
        expect(Array.from(key)).toEqual(Array.from(sym))
    })

    it('derives key from privkey for v2 header', () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)
        const { header, key: encKey } = newEciesHeader(recipientPub)

        const resolved = resolveDecryptionKey(undefined, recipientPriv, header)
        expect(Array.from(resolved)).toEqual(Array.from(encKey))
    })

    it('errors if v1 header but no symmetric key', () => {
        const hdr = new EncryptionHeader(SYMMETRIC_VERSION, new Uint8Array(16))
        expect(() => resolveDecryptionKey(undefined, undefined, hdr)).toThrow(
            /symmetric/i
        )
    })

    it('errors if v2 header but no private key', () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPub = secp256k1.getPublicKey(
            secp256k1.utils.randomPrivateKey(),
            true
        )
        const { header } = newEciesHeader(recipientPub)
        expect(() => resolveDecryptionKey(undefined, undefined, header)).toThrow(
            /private key/i
        )
    })

    it('errors if v1 symmetric key length is wrong', () => {
        const hdr = new EncryptionHeader(SYMMETRIC_VERSION, new Uint8Array(16))
        expect(() =>
            resolveDecryptionKey(new Uint8Array(31), undefined, hdr)
        ).toThrow(/32 bytes/)
    })
})
```

- [ ] **Step 2: Run the tests, expect failure**

Run:
```bash
pnpm exec jest tests/encryption.test.ts -t "decryptFragmentData|resolveDecryptionKey"
```
Expected: FAIL.

- [ ] **Step 3: Implement both functions**

Append to `src.ts/common/encryption.ts`:

```ts
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
```

- [ ] **Step 4: Run the full suite, expect pass**

Run:
```bash
pnpm exec jest tests/encryption.test.ts
```
Expected: PASS (all primitive suites).

- [ ] **Step 5: Commit**

```bash
git add src.ts/common/encryption.ts tests/encryption.test.ts
git commit -m "feat(encryption): add decryptFragmentData and resolveDecryptionKey"
```

---

## Task 9: EncryptedFile (AbstractFile wrapper)

**Files:**
- Create: `src.ts/file/EncryptedFile.ts`
- Create: `tests/encrypted_file.test.ts`

- [ ] **Step 1: Write failing tests**

Create `tests/encrypted_file.test.ts`:

```ts
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

        // First 17 bytes are the header; decrypt round-trips.
        const decrypted = decryptFile(key, buffer)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })

    it('readFromFile at an offset within the header region returns header bytes', async () => {
        const plain = new Uint8Array(100)
        const ef = newSymmetricEncryptedFile(
            new MemData(plain),
            new Uint8Array(32)
        )
        const { buffer } = await ef.readFromFile(0, 17)
        expect(buffer.length).toBe(17)
        expect(buffer[0]).toBe(0x01) // v1 version byte
    })
})

describe('EncryptedFile v2 (ECIES)', () => {
    it('prepends a 50-byte header and the inner can be decrypted with the matching privkey', async () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(500)
        for (let i = 0; i < plain.length; i++) plain[i] = i & 0xff
        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        expect(ef.size()).toBe(500 + ECIES_HEADER_SIZE)

        const { buffer } = await ef.readFromFile(0, ef.size())
        const header = parseEncryptionHeader(buffer)
        expect(header.version).toBe(0x02)

        const aesKey = deriveEciesDecryptKey(recipientPriv, header.ephemeralPub)
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

        // Collect all fragment bytes in order.
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
```

- [ ] **Step 2: Run the tests, expect failure**

Run:
```bash
pnpm exec jest tests/encrypted_file.test.ts
```
Expected: FAIL — `EncryptedFile` module does not exist.

- [ ] **Step 3: Create `src.ts/file/EncryptedFile.ts`**

```ts
import { AbstractFile } from './AbstractFile.js'
import { Iterator, MemIterator } from './Iterator/index.js'
import { iteratorPaddedSize } from './utils.js'
import {
    EncryptionHeader,
    newSymmetricHeader,
    newEciesHeader,
    cryptAt,
} from '../common/encryption.js'

// EncryptedFile wraps any AbstractFile with AES-256-CTR encryption. It
// prepends the header (17 bytes for v1, 50 bytes for v2) to the data stream
// and encrypts inner bytes on the fly when `readFromFile` is called. This
// is transparent to the Merkle-tree and segment pipelines.
export class EncryptedFile extends AbstractFile {
    inner: AbstractFile
    key: Uint8Array
    header: EncryptionHeader

    constructor(inner: AbstractFile, key: Uint8Array, header: EncryptionHeader) {
        super()
        this.inner = inner
        this.key = key
        this.header = header
        this.offset = 0
        this.size_ = inner.size() + header.size()
        this.paddedSize_ = iteratorPaddedSize(this.size_, true)
    }

    protected createFragment(
        offset: number,
        size: number,
        _paddedSize: number
    ): AbstractFile {
        return new EncryptedFileFragment(this, offset, size)
    }

    async readFromFile(
        start: number,
        end: number
    ): Promise<{ bytesRead: number; buffer: Uint8Array }> {
        if (start < 0 || start >= this.size() || start >= end) {
            throw new Error('invalid start offset')
        }
        if (end > this.size()) end = this.size()

        const total = end - start
        const buf = new Uint8Array(total)
        const headerSize = this.header.size()
        let written = 0

        // Copy any header bytes that fall within [start, end).
        if (start < headerSize) {
            const headerBytes = this.header.toBytes()
            const from = start
            const to = Math.min(headerSize, end)
            buf.set(headerBytes.slice(from, to), 0)
            written += to - from
        }

        // Copy encrypted inner data for the remainder.
        if (written < total) {
            const innerStart = start < headerSize ? 0 : start - headerSize
            const innerEnd = end - headerSize
            if (innerEnd > innerStart) {
                const inner = await this.inner.readFromFile(innerStart, innerEnd)
                const innerBuf = new Uint8Array(inner.buffer)
                cryptAt(this.key, this.header.nonce, innerStart, innerBuf)
                buf.set(innerBuf, written)
                written += innerBuf.length
            }
        }

        return { bytesRead: written, buffer: buf }
    }

    iterateWithOffsetAndBatch(
        offset: number,
        batch: number,
        flowPadding: boolean
    ): Iterator {
        // MemIterator pulls bytes via this.file.readFromFile (see
        // src.ts/file/Iterator/MemIterator.ts line 66) — EncryptedFile
        // overrides readFromFile, so MemIterator works unchanged.
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding)
        return new MemIterator(this, offset, batch, paddedSize)
    }
}

// Fragment of an EncryptedFile — delegates readFromFile to the parent with
// an offset adjustment.
export class EncryptedFileFragment extends AbstractFile {
    parent: EncryptedFile
    constructor(parent: EncryptedFile, offset: number, size: number) {
        super()
        this.parent = parent
        this.offset = offset
        this.size_ = size
        this.paddedSize_ = iteratorPaddedSize(size, true)
    }

    protected createFragment(
        _offset: number,
        _size: number,
        _paddedSize: number
    ): AbstractFile {
        // Fragments are not further splittable; mirror the Go reference.
        return this
    }

    async readFromFile(
        start: number,
        end: number
    ): Promise<{ bytesRead: number; buffer: Uint8Array }> {
        if (start < 0 || start >= this.size() || start >= end) {
            throw new Error('invalid start offset')
        }
        if (end > this.size()) end = this.size()
        return this.parent.readFromFile(this.offset + start, this.offset + end)
    }

    iterateWithOffsetAndBatch(
        offset: number,
        batch: number,
        flowPadding: boolean
    ): Iterator {
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding)
        return new MemIterator(this, offset, batch, paddedSize)
    }
}

// Convenience constructors matching the Go sdk's NewEncryptedData /
// NewEncryptedDataECIES.
export function newSymmetricEncryptedFile(
    inner: AbstractFile,
    key: Uint8Array
): EncryptedFile {
    if (key.length !== 32) throw new Error('key must be 32 bytes')
    return new EncryptedFile(inner, key, newSymmetricHeader())
}

export function newEciesEncryptedFile(
    inner: AbstractFile,
    recipientPub: Uint8Array | string
): EncryptedFile {
    const { header, key } = newEciesHeader(recipientPub)
    return new EncryptedFile(inner, key, header)
}
```

Check `src.ts/file/Iterator/MemIterator.ts` — if it already calls `readFromFile` on its source file (it should, based on `MemData.iterateWithOffsetAndBatch`), the `MemIteratorForEncrypted` subclass is a no-op pass-through. If MemIterator reads `.data` directly instead of `readFromFile`, **replace** `MemIteratorForEncrypted` with a minimal iterator that uses `readFromFile`. The test suite will flag this either way.

- [ ] **Step 4: Run the tests, expect pass**

Run:
```bash
pnpm exec jest tests/encrypted_file.test.ts
```
Expected: PASS. If the iterator path fails, inspect [src.ts/file/Iterator/MemIterator.ts](../../../src.ts/file/Iterator/MemIterator.ts) to confirm it pulls via `readFromFile` on the source `AbstractFile`. If not, update the local iterator class accordingly.

- [ ] **Step 5: Commit**

```bash
git add src.ts/file/EncryptedFile.ts tests/encrypted_file.test.ts
git commit -m "feat(file): add EncryptedFile wrapper for AbstractFile"
```

---

## Task 10: Wire encryption option into Uploader

**Files:**
- Modify: `src.ts/transfer/types.ts`
- Modify: `src.ts/transfer/Uploader.ts`

- [ ] **Step 1: Add the EncryptionOption type**

Edit `src.ts/transfer/types.ts` — add after the existing imports / types:

```ts
export type EncryptionOption =
    | { type: 'aes256'; key: Uint8Array }
    | { type: 'ecies'; recipientPubKey: Uint8Array | string }
```

Then add `encryption?: EncryptionOption` to the `UploadOption` interface (the one used by `Uploader.uploadFile` — locate by grepping for `interface UploadOption`).

- [ ] **Step 2: Wrap the file in Uploader.uploadFile**

Edit `src.ts/transfer/Uploader.ts`:
- Add import at the top:
  ```ts
  import {
      newSymmetricEncryptedFile,
      newEciesEncryptedFile,
  } from '../file/EncryptedFile.js'
  ```
- Inside `uploadFile`, immediately after `const mergedOpts = mergeUploadOptions(opts)` (currently around line 53), insert:
  ```ts
  if (mergedOpts.encryption) {
      file = wrapEncryption(file, mergedOpts.encryption)
  }
  ```
- Add the private method on the `Uploader` class:
  ```ts
  private wrapEncryption(
      file: AbstractFile,
      enc: EncryptionOption
  ): AbstractFile {
      switch (enc.type) {
          case 'aes256':
              return newSymmetricEncryptedFile(file, enc.key)
          case 'ecies':
              return newEciesEncryptedFile(file, enc.recipientPubKey)
      }
  }
  ```
  (Then reference it as `this.wrapEncryption(file, mergedOpts.encryption)` in place of the bare `wrapEncryption` call above.)

- Import `EncryptionOption` at the top of `Uploader.ts`:
  ```ts
  import { UploadOption, UploadTask, mergeUploadOptions, EncryptionOption } from './types.js'
  ```

- [ ] **Step 3: Build to catch type errors**

Run:
```bash
pnpm run build-esm
```
Expected: exit 0. If TypeScript complains that `file` parameter is `const`, change the `uploadFile` parameter declaration to `let file` via a local assignment:
```ts
async uploadFile(fileArg: AbstractFile, opts: UploadOption, retryOpts?: RetryOpts) {
    let file = fileArg
    // ...rest
}
```

- [ ] **Step 4: Sanity test — existing suite still passes**

Run:
```bash
pnpm test
```
Expected: PASS — no regressions in the existing tests. New upload-encryption integration is not yet exercised (download side not yet wired); confidence comes from `encrypted_file.test.ts` + the type-level check.

- [ ] **Step 5: Commit**

```bash
git add src.ts/transfer/types.ts src.ts/transfer/Uploader.ts
git commit -m "feat(transfer): wire EncryptionOption into Uploader"
```

---

## Task 11: Downloader — key setters and decrypt flow

**Files:**
- Modify: `src.ts/transfer/Downloader.ts`

- [ ] **Step 1: Add fields and setters**

At the top of `Downloader.ts`:

```ts
import {
    parseEncryptionHeader,
    resolveDecryptionKey,
    decryptFile,
    decryptFragmentData,
    EncryptionHeader,
    SYMMETRIC_HEADER_SIZE,
    ECIES_HEADER_SIZE,
    normalizePrivKey,
} from '../common/encryption.js'
```

Inside the `Downloader` class:

```ts
private symmetricKey?: Uint8Array
private privateKey?: Uint8Array

withSymmetricKey(key: Uint8Array | string): this {
    this.symmetricKey =
        typeof key === 'string' ? normalizePrivKey(key) : key
    return this
}

withPrivateKey(key: Uint8Array | string): this {
    this.privateKey = normalizePrivKey(key)
    return this
}

private hasDecryptionKey(): boolean {
    return this.symmetricKey !== undefined || this.privateKey !== undefined
}
```

Note: `normalizePrivKey` validates as a secp256k1 scalar. For `withSymmetricKey`, that validation is irrelevant (the bytes are an AES key, not a curve scalar) — use a plain length-32 check instead:

```ts
withSymmetricKey(key: Uint8Array | string): this {
    let bytes: Uint8Array
    if (typeof key === 'string') {
        const clean = key.startsWith('0x') ? key.slice(2) : key
        bytes = new Uint8Array(clean.length / 2)
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(clean.substr(i * 2, 2), 16)
        }
    } else {
        bytes = key
    }
    if (bytes.length !== 32) {
        throw new Error(
            `symmetric key must be 32 bytes, got ${bytes.length}`
        )
    }
    this.symmetricKey = bytes
    return this
}
```

- [ ] **Step 2: Decrypt the single-file download (filePath path)**

Modify `downloadFileHelper` (currently writes raw segments with `fs.appendFileSync`) to: (a) still write segments as-is if no decryption key is set, OR (b) collect segments into an in-memory buffer and decrypt, then write once.

Simpler approach: leave the existing segment-append logic unchanged, and add a post-download decrypt step. Change the end of `download(root, filePath, proof)` (or the bottom of `downloadFile`) to:

```ts
// existing segment download completes here...

if (this.hasDecryptionKey()) {
    const fs = await import(/* webpackIgnore: true */ 'fs')
    const encrypted = new Uint8Array(fs.readFileSync(filePath))
    const header = parseEncryptionHeader(encrypted)
    const aesKey = resolveDecryptionKey(
        this.symmetricKey,
        this.privateKey,
        header
    )
    const plaintext = decryptFile(aesKey, encrypted)
    fs.writeFileSync(filePath, plaintext)
}

return null
```

Insert immediately before the existing `return null` at the end of `downloadFileHelper`.

- [ ] **Step 3: Decrypt the in-memory Blob download**

Modify `downloadFileHelperToBlob` to, at the end:

```ts
const rawBlob = new Blob(chunks as unknown as BlobPart[])

if (this.hasDecryptionKey()) {
    const encrypted = new Uint8Array(await rawBlob.arrayBuffer())
    const header = parseEncryptionHeader(encrypted)
    const aesKey = resolveDecryptionKey(
        this.symmetricKey,
        this.privateKey,
        header
    )
    const plaintext = decryptFile(aesKey, encrypted)
    return [new Blob([plaintext]), null]
}

return [rawBlob, null]
```

- [ ] **Step 4: Decrypt the multi-root fragment downloads**

In `downloadFragments`:
- Before the per-root loop, declare:
  ```ts
  let encryptionHeader: EncryptionHeader | undefined
  let aesKey: Uint8Array | undefined
  let cumulativeDataOffset = 0
  const decrypting = this.hasDecryptionKey()
  ```
- Inside the per-root loop, after the temp file is fully written, replace the "copy temp contents into output file" block with:
  ```ts
  const fragmentBytes = new Uint8Array(fs.readFileSync(tempFile))

  let plaintext: Uint8Array
  if (decrypting) {
      if (encryptionHeader === undefined) {
          encryptionHeader = parseEncryptionHeader(fragmentBytes)
          aesKey = resolveDecryptionKey(
              this.symmetricKey,
              this.privateKey,
              encryptionHeader
          )
          const res = decryptFragmentData(
              aesKey,
              encryptionHeader,
              fragmentBytes,
              true,
              0
          )
          plaintext = res.plaintext
          cumulativeDataOffset = res.newOffset
      } else {
          const res = decryptFragmentData(
              aesKey!,
              encryptionHeader,
              fragmentBytes,
              false,
              cumulativeDataOffset
          )
          plaintext = res.plaintext
          cumulativeDataOffset = res.newOffset
      }
  } else {
      plaintext = fragmentBytes
  }

  fs.writeSync(outFileHandle, plaintext)
  ```

For `downloadFragmentsToBlob`, replace the loop body with the equivalent in-memory form:

```ts
const blobs: Blob[] = []
let encryptionHeader: EncryptionHeader | undefined
let aesKey: Uint8Array | undefined
let cumulativeDataOffset = 0
const decrypting = this.hasDecryptionKey()

for (const root of roots) {
    const [fragmentBlob, err] = await this.downloadFileToBlob(root, proof)
    if (err != null) {
        return [new Blob(), err]
    }

    if (!decrypting) {
        blobs.push(fragmentBlob)
        continue
    }

    const fragmentBytes = new Uint8Array(await fragmentBlob.arrayBuffer())
    let plaintext: Uint8Array
    if (encryptionHeader === undefined) {
        encryptionHeader = parseEncryptionHeader(fragmentBytes)
        aesKey = resolveDecryptionKey(
            this.symmetricKey,
            this.privateKey,
            encryptionHeader
        )
        const res = decryptFragmentData(
            aesKey,
            encryptionHeader,
            fragmentBytes,
            true,
            0
        )
        plaintext = res.plaintext
        cumulativeDataOffset = res.newOffset
    } else {
        const res = decryptFragmentData(
            aesKey!,
            encryptionHeader,
            fragmentBytes,
            false,
            cumulativeDataOffset
        )
        plaintext = res.plaintext
        cumulativeDataOffset = res.newOffset
    }
    blobs.push(new Blob([plaintext]))
}

return [new Blob(blobs), null]
```

Note: `downloadFileToBlob` currently triggers its own decrypt pass when a decryption key is set. To avoid double-decrypting, either call `downloadFileToBlobRaw` (if such a method exists) OR temporarily clear the decryption-key fields for the per-fragment download, then restore them. Simpler: factor the raw segment-download logic out of `downloadFileToBlob` into a private `downloadRawBlob(root, proof)` that does not trigger decryption, and have the single-root `downloadFileToBlob` + the multi-root `downloadFragmentsToBlob` call it. Do this refactor as part of Step 4 before writing the loop above.

- [ ] **Step 5: Run build + existing tests**

Run:
```bash
pnpm run build-esm && pnpm test
```
Expected: exit 0, all existing tests pass. If TypeScript flags `SYMMETRIC_HEADER_SIZE`/`ECIES_HEADER_SIZE` as unused, remove those imports (they're only used if you add a header-size-sanity check).

- [ ] **Step 6: Add an end-to-end encryption integration test (v1)**

Append to `tests/encrypted_file.test.ts`:

```ts
describe('Upload/Download round-trip via primitives only', () => {
    // We exercise the primitives rather than standing up a StorageNode mock,
    // since hitting real nodes is out of scope for unit tests. This covers
    // the seam the Uploader/Downloader rely on: encrypt a file, simulate the
    // upload-then-download pipeline by transporting the raw bytes, and
    // decrypt them back.

    it('v1: EncryptedFile bytes decrypt back via decryptFile', async () => {
        const plain = new Uint8Array(2048)
        for (let i = 0; i < plain.length; i++) plain[i] = (i * 31) & 0xff
        const key = new Uint8Array(32).fill(0x99)

        const ef = newSymmetricEncryptedFile(new MemData(plain), key)
        const { buffer: transported } = await ef.readFromFile(0, ef.size())
        const decrypted = decryptFile(key, transported)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })

    it('v2: EncryptedFile bytes decrypt back with recipient privkey', async () => {
        const { secp256k1 } = require('@noble/curves/secp256k1')
        const recipientPriv = secp256k1.utils.randomPrivateKey()
        const recipientPub = secp256k1.getPublicKey(recipientPriv, true)

        const plain = new Uint8Array(5000)
        for (let i = 0; i < plain.length; i++) plain[i] = (i ^ 0xa5) & 0xff

        const ef = newEciesEncryptedFile(new MemData(plain), recipientPub)
        const { buffer: transported } = await ef.readFromFile(0, ef.size())

        const header = parseEncryptionHeader(transported)
        const aesKey = deriveEciesDecryptKey(recipientPriv, header.ephemeralPub)
        const decrypted = decryptFile(aesKey, transported)
        expect(Array.from(decrypted)).toEqual(Array.from(plain))
    })
})
```

Run:
```bash
pnpm exec jest tests/encrypted_file.test.ts -t "Upload/Download round-trip"
```
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add src.ts/transfer/Downloader.ts tests/encrypted_file.test.ts
git commit -m "feat(transfer): add Downloader withSymmetricKey/withPrivateKey and decrypt flow"
```

---

## Task 12: Public API re-exports

**Files:**
- Modify: `src.ts/common/index.ts`
- Modify: `src.ts/file/index.ts`
- Modify: `src.ts/index.ts`

- [ ] **Step 1: Re-export from `src.ts/common/index.ts`**

Add to `src.ts/common/index.ts` (preserve existing exports):

```ts
export {
    EncryptionHeader,
    parseEncryptionHeader,
    newSymmetricHeader,
    newEciesHeader,
    cryptAt,
    decryptFile,
    decryptFragmentData,
    resolveDecryptionKey,
    deriveEciesEncryptKey,
    deriveEciesDecryptKey,
    normalizePubKey,
    normalizePrivKey,
    SYMMETRIC_VERSION,
    ECIES_VERSION,
    SYMMETRIC_HEADER_SIZE,
    ECIES_HEADER_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
} from './encryption.js'
```

- [ ] **Step 2: Re-export from `src.ts/file/index.ts`**

Add to `src.ts/file/index.ts`:

```ts
export {
    EncryptedFile,
    EncryptedFileFragment,
    newSymmetricEncryptedFile,
    newEciesEncryptedFile,
} from './EncryptedFile.js'
```

- [ ] **Step 3: Re-export from `src.ts/index.ts`**

If `src.ts/index.ts` uses barrel-style `export * from './common/index.js'` / `export * from './file/index.js'`, no change needed — the new symbols are already bubbled up. Otherwise, add explicit exports for the encryption primitives and the `EncryptionOption` type.

Verify by grepping:
```bash
pnpm exec grep -n "from './common/" src.ts/index.ts src.ts/index.js 2>/dev/null
```

- [ ] **Step 4: Export `EncryptionOption` from transfer**

In `src.ts/transfer/index.ts`, ensure `EncryptionOption` is exported alongside `UploadOption`. Grep for `UploadOption` in the file and add `EncryptionOption` next to it.

- [ ] **Step 5: Build end-to-end**

Run:
```bash
pnpm run build-all
```
Expected: exit 0, no TypeScript errors.

- [ ] **Step 6: Commit**

```bash
git add src.ts/common/index.ts src.ts/file/index.ts src.ts/index.ts src.ts/transfer/index.ts
git commit -m "feat: re-export encryption primitives and types"
```

---

## Task 13: Final acceptance verification

**Files:**
- None (verification only)

- [ ] **Step 1: Run the full test suite**

Run:
```bash
pnpm test
```
Expected: exit 0, all tests pass (existing `MerkleTree.test.js`, `Provider.test.js`, `shard.test.js`, `ZgFile.test.js` plus new `encryption.test.ts`, `encrypted_file.test.ts`).

- [ ] **Step 2: Run the full build**

Run:
```bash
pnpm run build-all
```
Expected: exit 0. Confirms ESM + CJS + types compile cleanly.

- [ ] **Step 3: Confirm public API surface**

Run:
```bash
pnpm exec node -e "const m=require('./lib.commonjs/index.js'); console.log(Object.keys(m).filter(k=>/[Ee]ncrypt|Ecies|crypt|normalize|SYMMETRIC|ECIES/.test(k)))"
```
Expected: list includes `EncryptionHeader`, `EncryptedFile`, `cryptAt`, `decryptFile`, `newSymmetricEncryptedFile`, `newEciesEncryptedFile`, `deriveEciesEncryptKey`, `deriveEciesDecryptKey`, `resolveDecryptionKey`, `normalizePubKey`, `normalizePrivKey`, the `SYMMETRIC_*` / `ECIES_*` constants.

- [ ] **Step 4: Check that Uploader and Downloader types expose the new options**

Run:
```bash
pnpm exec tsc --noEmit --project tsconfig.esm.json
```
Expected: exit 0.

- [ ] **Step 5: Tag completion**

The acceptance criterion (`pnpm test` passes) is met. No additional commit needed — verification was reads only.

---

## Self-review notes

- **Spec coverage:** every section of the spec maps to at least one task.
  - Header format (v1, v2) → Tasks 2, 3.
  - HKDF info literal → Task 6 (embedded as `ECIES_HKDF_INFO`).
  - `cryptAt` + big-endian counter → Task 4.
  - ECDH via `@noble/curves`, strip prefix → Task 6.
  - Key normalization (`normalizePubKey`, `normalizePrivKey`) → Task 5.
  - `EncryptionHeader`, factories, `decryptFile`, `decryptFragmentData`, `resolveDecryptionKey` → Tasks 2, 3, 7, 8.
  - `EncryptedFile` + `EncryptedFileFragment` → Task 9.
  - `UploadOption.encryption` discriminated union → Task 10.
  - `withSymmetricKey` + `withPrivateKey` + decrypt flow → Task 11.
  - Re-exports → Task 12.
  - `pnpm test` passes → Task 13.

- **Library caveat:** `@noble/hashes/utils.randomBytes` (used in Task 7) is a supported export; if the install yields a different structure, swap to `crypto.randomBytes` (Node) or `crypto.getRandomValues` (browser) with a Platform switch. Noble currently ships `randomBytes` on `@noble/hashes/utils`.

- **Iterator integration (Task 9):** verified — [src.ts/file/Iterator/MemIterator.ts:32,66](../../../src.ts/file/Iterator/MemIterator.ts) pulls bytes via `this.file.readFromFile`, so `EncryptedFile` plugs in directly with no custom iterator subclass.

- **Refactor hint for Task 11 step 4 (Blob multi-root):** the per-root call to `downloadFileToBlob` triggers its own decrypt when a key is set, which would double-decrypt the fragment. The step notes this and asks you to factor out a raw-segment-download helper — do that refactor before writing the loop, not after.

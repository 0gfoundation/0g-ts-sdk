# ts-sdk v1 + v2 (ECIES) encryption design

## Purpose

Add AES-256-CTR encryption to the 0G ts-sdk, wire-compatible with the Go
client's `feat: add ECIES (asymmetric) encryption alongside symmetric
AES-256` commit (`0g-storage-client` @ 6d39443). Two schemes:

- **v1 (symmetric).** Caller supplies a 32-byte AES key.
- **v2 (ECIES).** Caller supplies a recipient secp256k1 pubkey on encrypt
  and the matching private key on decrypt. Enables "encrypt to my wallet,
  decrypt with my wallet" flows on the frontend.

The ts-sdk must round-trip with files produced by the Go client in both
directions: a file written by the Go CLI is decryptable by the ts-sdk,
and vice versa. The wire format, HKDF info literal, CTR counter
construction, and header shapes are all fixed by the Go reference.

## Non-goals

- Authenticated encryption. AES-256-CTR provides confidentiality only.
  The Go scheme uses Merkle-root integrity at the storage layer; we
  match.
- Streaming decrypt. The Go reference reads the full downloaded file
  into memory before decrypting. We match. Large-file streaming decrypt
  can be revisited later if needed.
- MetaMask-style wallets that do not expose the private key. True
  secp256k1 ECIES requires direct access to the recipient private key.
  Wallets that gate the key behind an RPC (MetaMask `eth_decrypt` uses
  Curve25519/NaCl, not secp256k1) are not usable with this scheme; the
  frontend must either hold a privkey directly or invent a
  signature-derived symmetric scheme (out of scope).
- KV module code changes. `src.ts/kv/batcher.ts:49` passes the caller's
  `UploadOption` straight into `Uploader.uploadFile`, so adding
  `encryption` to `UploadOption` lights up KV automatically. No KV
  changes are required in this spec.

## Wire format (fixed by Go)

### v1 header — 17 bytes

```
[version:1 = 0x01][nonce:16]
```

The AES-256 key is caller-supplied out-of-band.

### v2 header — 50 bytes

```
[version:1 = 0x02][ephemeralPubCompressed:33][nonce:16]
```

The AES-256 key is derived from ECDH(ephemeralPriv, recipientPub) run
through HKDF-SHA256.

**HKDF info literal — MUST match Go byte-for-byte:**

```
0g-storage-client/ecies/v1/aes-256
```

Salt is empty. `sha256` as hash. Output length 32 bytes.

### Bulk cipher — AES-256-CTR, 128-bit big-endian counter

The counter at plaintext byte offset `o` is:

```
counter = nonce + floor(o / 16)    // big-endian 128-bit add with carry
byteSkip = o mod 16                // keystream bytes to discard before XOR
```

This construction is required so that a fragment decrypted starting at
offset `o` produces bit-identical output to the same bytes recovered
from a full-file decrypt. Verified that `@noble/ciphers` CTR increments
its 16-byte IV as a 128-bit big-endian counter, matching Go's
`crypto/cipher.NewCTR`.

### Format dispatch

The header is parsed by reading byte 0, then switching on version:
0x01 → 17-byte v1 header, 0x02 → 50-byte v2 header, anything else →
error. Old v1 files never need migration.

## Architecture

### New files

- `src.ts/common/encryption.ts` — primitives. Exports:
  - `EncryptionHeader` class: `version`, `nonce: Uint8Array(16)`,
    `ephemeralPub: Uint8Array(33)` (zero for v1). Methods: `toBytes()`,
    `size()`.
  - `parseEncryptionHeader(data: Uint8Array): EncryptionHeader`
  - `newSymmetricHeader(): EncryptionHeader` — fresh random nonce
  - `newEciesHeader(recipientPub): { header, key }` — fresh ephemeral,
    derived AES key
  - `cryptAt(key, nonce, offset, data)` — in-place AES-256-CTR XOR
  - `deriveEciesEncryptKey(recipientPub)` → `{ key, ephemeralPub }`
  - `deriveEciesDecryptKey(recipientPriv, ephemeralPub)` → `key`
  - `decryptFile(key, encrypted)` → plaintext (strips header,
    decrypts remainder at offset 0)
  - `decryptFragmentData(key, header, fragmentData, isFirstFragment,
    dataOffset)` → `{ plaintext, newOffset }`
  - `resolveDecryptionKey(symmetricKey?, privateKey?, header)` → key,
    errors cleanly on missing-material-for-this-version

- `src.ts/file/EncryptedFile.ts` — wraps an inner `AbstractFile`:
  - `EncryptedFile extends AbstractFile` — `size = inner.size +
    header.size`. `readFromFile(start, end)` returns header bytes for
    `start < headerSize`, otherwise reads inner and calls
    `cryptAt(key, nonce, start - headerSize, buf)`.
  - `iterateWithOffsetAndBatch` uses the existing `MemIterator` /
    `BlobIterator` by reading through `readFromFile` — no iterator
    subclass needed. The encryption is transparent to the Merkle tree
    and segment-upload pipeline.
  - `split(fragmentSize)` returns `EncryptedFileFragment[]`. Fragment 0
    contains the header; subsequent fragments are pure encrypted
    payload. Fragments delegate `readFromFile` to the parent with an
    offset adjustment.

- `tests/encryption.test.ts` — header roundtrip (v1, v2), `cryptAt`
  roundtrip at offset 0 and at non-zero offset, offset-decrypts-match-
  full-decrypt, ECIES derive key roundtrip, wrong privkey yields wrong
  key, unsupported version rejected, too-short header rejected.

- `tests/encrypted_file.test.ts` — wraps `MemData` in `EncryptedFile`,
  reads the full stream in one pass and as fragments, verifies
  `decryptFile` / `decryptFragmentData` roundtrip to the original for
  both v1 and v2.

### Modified files

- `src.ts/transfer/types.ts` — extend `UploadOption`:
  ```ts
  type EncryptionOption =
    | { type: 'aes256'; key: Uint8Array }
    | { type: 'ecies'; recipientPubKey: Uint8Array | string }

  interface UploadOption {
    // ...existing fields...
    encryption?: EncryptionOption
  }
  ```
  Discriminated union — type system enforces "one scheme per upload",
  no runtime mutual-exclusion check needed.

- `src.ts/transfer/Uploader.ts` — new private
  `wrapEncryption(file, opts)` that returns the input `file` unchanged
  when `opts.encryption` is undefined, an `EncryptedFile` wrapping
  `file` otherwise. Called once at the top of `uploadFile` before the
  Merkle tree step, so the tree, segments, and submission are all
  computed over the encrypted stream.

- `src.ts/transfer/Downloader.ts` — two fluent setters:
  ```ts
  withSymmetricKey(key: Uint8Array | string): this // for v1 files
  withPrivateKey(key: Uint8Array | string): this   // for v2 files
  ```
  Both accept hex or bytes via `normalizePrivKey` / a 32-byte equivalent
  to keep the two setters symmetric and frontend-ergonomic.
  Both additive; either or both may be set. After segment download
  completes, the downloader parses the first-header-sized bytes to read
  the version, calls `resolveDecryptionKey` to pick the right key, then
  runs `decryptFile` (single-root path) or iterates
  `decryptFragmentData` (multi-root path) to produce plaintext. Dispatch
  is: if either setter was called, try to decrypt; if neither, return
  raw bytes (matches Go `hasDecryptionKey()` behavior).

- `src.ts/common/index.ts` — re-export `EncryptionHeader`, the
  primitives, `EncryptionOption`.
- `src.ts/file/index.ts` — re-export `EncryptedFile`,
  `EncryptedFileFragment`.
- `src.ts/index.ts` — re-export public entry points from the above.
- `package.json` — add `@noble/curves`, `@noble/hashes`,
  `@noble/ciphers` as `dependencies`. The first two are already
  transitive deps via ethers; declaring them direct is free and makes
  the dependency surface explicit. `@noble/ciphers` is new.

## Key normalization

Single shared helpers inside `encryption.ts`, unexported:

- `normalizePubKey(input: Uint8Array | string): Uint8Array(33)` —
  accepts 33-byte compressed bytes, 65-byte uncompressed bytes
  (`0x04||x||y`), 64-byte uncompressed without prefix, or hex strings
  of any of the above (with or without `0x`). Returns compressed
  33-byte bytes. Uses `@noble/curves/secp256k1` for point compression.

- `normalizePrivKey(input: Uint8Array | string): Uint8Array(32)` —
  accepts 32-byte raw or 32-byte hex (with or without `0x`). Returns
  32-byte bytes. Rejects invalid scalars via noble's validator.

## ECDH step

```ts
import { secp256k1 } from '@noble/curves/secp256k1'

const sharedPointCompressed =
  secp256k1.getSharedSecret(privKey, pubKey, true)  // 33 bytes: 0x02/0x03 || x
const sharedX = sharedPointCompressed.slice(1)       // 32 bytes: x only
```

This matches go-ethereum's `ecies.GenerateShared`, which returns just
the x-coordinate (32 bytes) of the shared point. `sharedX` is the input
to HKDF.

## HKDF step

```ts
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'

const info = new TextEncoder().encode(
  '0g-storage-client/ecies/v1/aes-256'
)
const aesKey = hkdf(sha256, sharedX, new Uint8Array(0), info, 32)
```

Byte-identical to Go's `hkdf.New(sha256.New, shared, nil, eciesHKDFInfo)`
followed by `io.ReadFull(reader, out[:32])`.

## AES-256-CTR step

```ts
import { ctr } from '@noble/ciphers/aes'

// `counter` is a 16-byte Uint8Array pre-adjusted for the offset
// (nonce + blockOffset with big-endian carry). `byteSkip` is offset % 16.
const cipher = ctr(key, counter)
if (byteSkip > 0) {
  cipher.encrypt(new Uint8Array(byteSkip))  // discard keystream
}
const out = cipher.encrypt(data)  // or in-place XOR
```

Wrapper `cryptAt(key, nonce, offset, data)` hides the counter math and
keystream-skip; callers pass `offset` in plaintext bytes.

## Downloader decrypt flow

### Single root — `Downloader.download(root, filePath)` / `downloadToBlob(root)`

1. Download segments as today; assemble raw encrypted bytes (on disk
   or in a Blob).
2. If at least one decryption key setter was called:
   a. Read the bytes back into memory.
   b. `parseEncryptionHeader(encrypted)` → version + nonce (+
      ephemeralPub for v2).
   c. `resolveDecryptionKey(symmetricKey, privateKey, header)` → 32-byte
      AES key; errors if the required material for this version is
      missing.
   d. `decryptFile(key, encrypted)` → plaintext.
   e. Write plaintext to the output path or return it as a Blob.
3. If no key setter was called: return the raw bytes as-is (matches
   Go).

### Multi-root — `downloadFragments(roots, filePath)` / `downloadFragmentsToBlob(roots)`

Mirrors Go's `downloadEncryptedFragments`:

1. For each root in order: download to a temp file/buffer.
2. For fragment 0: parse header from the first bytes, call
   `resolveDecryptionKey` once, then `decryptFragmentData(key, header,
   bytes, true, 0)` → plaintext and `cumulativeOffset = len(plaintext)`.
3. For fragments 1..N-1: `decryptFragmentData(key, header, bytes,
   false, cumulativeOffset)` → plaintext, advance offset.
4. Append plaintext to the output; drop the temp buffer.

## Testing

Two suites:

1. **`tests/encryption.test.ts`** — unit tests of the primitives. Covers
   header parse/serialize for v1 and v2, `cryptAt` roundtrip at offset
   0 and at non-zero offset, offset-decrypt matches full-decrypt slice,
   ECIES derive-key roundtrip, wrong-privkey-differs-from-right-privkey,
   parse rejects unsupported version / too-short headers,
   `resolveDecryptionKey` errors cleanly when the required material is
   missing for the header version.

   End-to-end interop with the Go client is validated out-of-band
   (upload via Go CLI, decrypt via ts-sdk and vice versa) rather than
   via precomputed hex vectors. Keeps the test suite pure-TS.

2. **`tests/encrypted_file.test.ts`** — integration at the file-wrapper
   level. Wraps `MemData` in `EncryptedFile`, reads the full stream,
   decrypts via `decryptFile`, asserts equality with original. Repeats
   over `.split(fragmentSize)` for multiple fragment-size configurations
   (single fragment, even-split, uneven-split). Runs for both v1 and
   v2.

## Public API surface summary

```ts
// Upload — one new optional field
uploader.uploadFile(file, {
  encryption: { type: 'aes256', key: bytes32 },
  // or
  encryption: { type: 'ecies', recipientPubKey: compressedPubOrHex },
})

// Download — two new fluent setters
downloader
  .withSymmetricKey(bytes32OrHex)
  .withPrivateKey(bytes32OrHex)
  .download(root, path)
```

No rename of existing methods; existing callers are unaffected when
`encryption` is absent and no setters are called.

## Open questions

None. All scope and compatibility questions resolved during design
conversation.

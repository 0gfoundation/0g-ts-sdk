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

    constructor(
        inner: AbstractFile,
        key: Uint8Array,
        header: EncryptionHeader
    ) {
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
                const inner = await this.inner.readFromFile(
                    innerStart,
                    innerEnd
                )
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
        // MemIterator pulls bytes via this.file.readFromFile
        // (src.ts/file/Iterator/MemIterator.ts line 66) — EncryptedFile
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

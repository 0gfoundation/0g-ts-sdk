import { Iterator, BlobIterator } from './Iterator/index.js'
import { AbstractFile } from './AbstractFile.js'
import { iteratorPaddedSize } from './utils.js'

export class Blob extends AbstractFile {
    blob: File | null = null // @see https://developer.mozilla.org/en-US/docs/Web/API/File/File

    constructor(
        blob: File,
        offset: number = 0,
        size?: number,
        paddedSize?: number
    ) {
        super()
        this.blob = blob
        this.offset = offset
        this.size_ = size ?? blob.size
        this.paddedSize_ = paddedSize ?? iteratorPaddedSize(this.size_, true)
    }

    protected createFragment(
        offset: number,
        size: number,
        paddedSize: number
    ): AbstractFile {
        return new Blob(this.blob!, offset, size, paddedSize)
    }

    async readFromFile(
        start: number,
        end: number
    ): Promise<{ bytesRead: number; buffer: Uint8Array }> {
        if (start < 0 || start >= this.size() || start >= end) {
            throw new Error('invalid start offset')
        }
        if (end > this.size()) {
            end = this.size()
        }

        const sliceStart = this.offset + start
        const sliceEnd = this.offset + end
        const arrayBuffer = await this.blob!.slice(
            sliceStart,
            sliceEnd
        ).arrayBuffer()
        const buffer = new Uint8Array(arrayBuffer)

        return {
            bytesRead: buffer.length,
            buffer,
        }
    }

    iterateWithOffsetAndBatch(
        offset: number,
        batch: number,
        flowPadding: boolean
    ): Iterator {
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding)
        return new BlobIterator(this, offset, batch, paddedSize)
    }
}

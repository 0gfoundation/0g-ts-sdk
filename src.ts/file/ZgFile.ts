import { open, FileHandle } from 'node:fs/promises'
import { Iterator, BlobIterator } from './Iterator/index.js'
import { AbstractFile } from './AbstractFile.js'
import { iteratorPaddedSize } from './utils.js'

export class ZgFile extends AbstractFile {
    fd: FileHandle | null = null

    constructor(
        fd: FileHandle,
        offset: number = 0,
        size?: number,
        paddedSize?: number
    ) {
        super()
        this.fd = fd
        this.offset = offset
        this.size_ = size ?? 0
        this.paddedSize_ = paddedSize ?? iteratorPaddedSize(this.size_, true)
    }

    static async fromNodeFileHandle(fd: FileHandle): Promise<ZgFile> {
        const stat = await fd.stat()
        return new ZgFile(fd, 0, stat.size)
    }

    // NOTE: need manually close fd after use
    static async fromFilePath(path: string): Promise<ZgFile> {
        const fd = await open(path, 'r') // if fail, throw error
        return await ZgFile.fromNodeFileHandle(fd)
    }

    async close(): Promise<void> {
        await this.fd?.close()
    }

    protected createFragment(
        offset: number,
        size: number,
        paddedSize: number
    ): AbstractFile {
        return new ZgFile(this.fd!, offset, size, paddedSize)
    }

    async readFromFile(
        start: number,
        end: number
    ): Promise<{ bytesRead: number; buffer: Uint8Array }> {
        if (start < 0 || start >= this.size()) {
            throw new Error('invalid start offset')
        }
        if (end > this.size()) {
            end = this.size()
        }

        const buffer = new Uint8Array(end - start)
        const result = await this.fd?.read({
            buffer,
            offset: 0,
            length: end - start,
            position: this.offset + start,
        })

        return {
            bytesRead: result?.bytesRead || 0,
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

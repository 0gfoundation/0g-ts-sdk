import { open } from 'node:fs/promises';
import { BlobIterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
import { iteratorPaddedSize } from './utils.js';
export class ZgFile extends AbstractFile {
    fd = null;
    constructor(fd, offset = 0, size, paddedSize) {
        super();
        this.fd = fd;
        this.offset = offset;
        this.size_ = size ?? 0;
        this.paddedSize_ = paddedSize ?? iteratorPaddedSize(this.size_, true);
    }
    static async fromNodeFileHandle(fd) {
        const stat = await fd.stat();
        return new ZgFile(fd, 0, stat.size);
    }
    // NOTE: need manually close fd after use
    static async fromFilePath(path) {
        const fd = await open(path, 'r'); // if fail, throw error
        return await ZgFile.fromNodeFileHandle(fd);
    }
    async close() {
        await this.fd?.close();
    }
    createFragment(offset, size, paddedSize) {
        return new ZgFile(this.fd, offset, size, paddedSize);
    }
    async readFromFile(start, end) {
        if (start < 0 || start >= this.size()) {
            throw new Error('invalid start offset');
        }
        if (end > this.size()) {
            end = this.size();
        }
        const buffer = new Uint8Array(end - start);
        const result = await this.fd?.read({
            buffer,
            offset: 0,
            length: end - start,
            position: this.offset + start,
        });
        return {
            bytesRead: result?.bytesRead || 0,
            buffer,
        };
    }
    iterateWithOffsetAndBatch(offset, batch, flowPadding) {
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding);
        return new BlobIterator(this, offset, batch, paddedSize);
    }
}
//# sourceMappingURL=ZgFile.js.map
import { BlobIterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
import { iteratorPaddedSize } from './utils.js';
export class Blob extends AbstractFile {
    blob = null; // @see https://developer.mozilla.org/en-US/docs/Web/API/File/File
    constructor(blob, offset = 0, size, paddedSize) {
        super();
        this.blob = blob;
        this.offset = offset;
        this.size_ = size ?? blob.size;
        this.paddedSize_ = paddedSize ?? iteratorPaddedSize(this.size_, true);
    }
    createFragment(offset, size, paddedSize) {
        return new Blob(this.blob, offset, size, paddedSize);
    }
    async readFromFile(start, end) {
        if (start < 0 || start >= this.size()) {
            throw new Error('invalid start offset');
        }
        if (end > this.size()) {
            end = this.size();
        }
        const sliceStart = this.offset + start;
        const sliceEnd = this.offset + end;
        const arrayBuffer = await this.blob.slice(sliceStart, sliceEnd).arrayBuffer();
        const buffer = new Uint8Array(arrayBuffer);
        return {
            bytesRead: buffer.length,
            buffer,
        };
    }
    iterateWithOffsetAndBatch(offset, batch, flowPadding) {
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding);
        return new BlobIterator(this, offset, batch, paddedSize);
    }
}
//# sourceMappingURL=Blob.js.map
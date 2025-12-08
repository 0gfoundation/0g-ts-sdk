import { MemIterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
import { iteratorPaddedSize } from './utils.js';
export class MemData extends AbstractFile {
    data;
    constructor(data, offset = 0, size, paddedSize) {
        super();
        this.data = data;
        this.offset = offset;
        this.size_ = size ?? data.length;
        this.paddedSize_ = paddedSize ?? iteratorPaddedSize(this.size_, true);
    }
    createFragment(offset, size, paddedSize) {
        return new MemData(this.data, offset, size, paddedSize);
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
        const sliced = new Uint8Array(this.data).slice(sliceStart, sliceEnd);
        return {
            bytesRead: sliced.length,
            buffer: sliced,
        };
    }
    iterateWithOffsetAndBatch(offset, batch, flowPadding) {
        const paddedSize = iteratorPaddedSize(this.size(), flowPadding);
        return new MemIterator(this, offset, batch, paddedSize);
    }
}
//# sourceMappingURL=MemData.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemData = void 0;
const index_js_1 = require("./Iterator/index.js");
const AbstractFile_js_1 = require("./AbstractFile.js");
const utils_js_1 = require("./utils.js");
class MemData extends AbstractFile_js_1.AbstractFile {
    data;
    constructor(data, offset = 0, size, paddedSize) {
        super();
        this.data = data;
        this.offset = offset;
        this.size_ = size ?? data.length;
        this.paddedSize_ = paddedSize ?? (0, utils_js_1.iteratorPaddedSize)(this.size_, true);
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
        const paddedSize = (0, utils_js_1.iteratorPaddedSize)(this.size(), flowPadding);
        return new index_js_1.MemIterator(this, offset, batch, paddedSize);
    }
}
exports.MemData = MemData;
//# sourceMappingURL=MemData.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Blob = void 0;
const index_js_1 = require("./Iterator/index.js");
const AbstractFile_js_1 = require("./AbstractFile.js");
const utils_js_1 = require("./utils.js");
class Blob extends AbstractFile_js_1.AbstractFile {
    blob = null; // @see https://developer.mozilla.org/en-US/docs/Web/API/File/File
    constructor(blob, offset = 0, size, paddedSize) {
        super();
        this.blob = blob;
        this.offset = offset;
        this.size_ = size ?? blob.size;
        this.paddedSize_ = paddedSize ?? (0, utils_js_1.iteratorPaddedSize)(this.size_, true);
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
        const paddedSize = (0, utils_js_1.iteratorPaddedSize)(this.size(), flowPadding);
        return new index_js_1.BlobIterator(this, offset, batch, paddedSize);
    }
}
exports.Blob = Blob;
//# sourceMappingURL=Blob.js.map
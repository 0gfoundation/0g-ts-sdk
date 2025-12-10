"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BlobIterator = void 0;
const constant_js_1 = require("../../constant.js");
class BlobIterator {
    file;
    buf;
    bufSize = 0; // buffer content size
    fileSize;
    paddedSize; // total size including padding zeros
    offset = 0;
    batchSize;
    constructor(file, offset, batch, paddedSize) {
        if (batch % constant_js_1.DEFAULT_CHUNK_SIZE > 0) {
            throw new Error("batch size should align with chunk size");
        }
        const buf = new Uint8Array(batch);
        this.file = file;
        this.buf = buf;
        this.fileSize = file.size();
        this.paddedSize = paddedSize;
        this.batchSize = batch;
        this.offset = offset;
    }
    async readFromFile(start, end) {
        return await this.file.readFromFile(start, end);
    }
    clearBuffer() {
        this.bufSize = 0;
    }
    paddingZeros(length) {
        const startOffset = this.bufSize;
        this.buf = this.buf.fill(0, startOffset, startOffset + length);
        this.bufSize += length;
        this.offset += length;
    }
    async next() {
        if (this.offset < 0 || this.offset >= this.paddedSize) {
            return [false, null];
        }
        let expectedBufSize;
        let maxAvailableLength = this.paddedSize - this.offset; // include padding zeros
        if (maxAvailableLength >= this.batchSize) {
            expectedBufSize = this.batchSize;
        }
        else {
            expectedBufSize = maxAvailableLength;
        }
        this.clearBuffer();
        if (this.offset >= this.fileSize) {
            this.paddingZeros(expectedBufSize);
            return [true, null];
        }
        const { bytesRead: n, buffer } = await this.readFromFile(this.offset, this.offset + this.batchSize);
        this.buf = buffer;
        this.bufSize = n;
        this.offset += n;
        // not reach EOF
        if (n === expectedBufSize) {
            return [true, null];
        }
        if (n > expectedBufSize) {
            // should never happen
            throw new Error("load more data from file than expected");
        }
        if (expectedBufSize > n) {
            this.paddingZeros(expectedBufSize - n);
        }
        return [true, null];
    }
    current() {
        return this.buf.subarray(0, this.bufSize);
    }
}
exports.BlobIterator = BlobIterator;
//# sourceMappingURL=BlobIterator.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZgFile = void 0;
const promises_1 = require("node:fs/promises");
const index_js_1 = require("./Iterator/index.js");
const AbstractFile_js_1 = require("./AbstractFile.js");
const utils_js_1 = require("./utils.js");
class ZgFile extends AbstractFile_js_1.AbstractFile {
    fd = null;
    constructor(fd, offset = 0, size, paddedSize) {
        super();
        this.fd = fd;
        this.offset = offset;
        this.size_ = size ?? 0;
        this.paddedSize_ = paddedSize ?? (0, utils_js_1.iteratorPaddedSize)(this.size_, true);
    }
    static async fromNodeFileHandle(fd) {
        const stat = await fd.stat();
        return new ZgFile(fd, 0, stat.size);
    }
    // NOTE: need manually close fd after use
    static async fromFilePath(path) {
        const fd = await (0, promises_1.open)(path, 'r'); // if fail, throw error
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
        const paddedSize = (0, utils_js_1.iteratorPaddedSize)(this.size(), flowPadding);
        return new index_js_1.BlobIterator(this, offset, batch, paddedSize);
    }
}
exports.ZgFile = ZgFile;
//# sourceMappingURL=ZgFile.js.map
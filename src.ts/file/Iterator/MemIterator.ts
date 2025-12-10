import { Iterator } from './Iterator.js';
import {
    DEFAULT_CHUNK_SIZE, 
} from '../../constant.js';
import { AbstractFile } from '../AbstractFile.js';

export class MemIterator implements Iterator {
    file: AbstractFile
    buf: Uint8Array;
    bufSize: number = 0; // buffer content size
    fileSize: number;
    paddedSize: number; // total size including padding zeros
    offset: number = 0;
    batchSize: number;

    constructor(file: AbstractFile, offset: number, batch: number, paddedSize: number) {
        if (batch % DEFAULT_CHUNK_SIZE > 0) {
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

    async readFromFile(start: number, end: number): Promise<{bytesRead: number, buffer: Uint8Array}> {
        return await this.file.readFromFile(start, end)
    }

    clearBuffer() {
        this.bufSize = 0;
    }

    paddingZeros(length: number) {
        const startOffset = this.bufSize;
        this.buf = this.buf.fill(0, startOffset, startOffset + length);
        this.bufSize += length;
        this.offset += length;
    }

    async next(): Promise<[boolean, Error | null]> {
        if (this.offset < 0 || this.offset >= this.paddedSize) {
            return [false, null];
        }

        let expectedBufSize;
        let maxAvailableLength = this.paddedSize - this.offset;  // include padding zeros
        if (maxAvailableLength >= this.batchSize) {
            expectedBufSize = this.batchSize;
        } else {
            expectedBufSize = maxAvailableLength;
        }

        this.clearBuffer()

        if (this.offset >= this.fileSize) {
            this.paddingZeros(expectedBufSize);
            return [true, null];
        }

        const {bytesRead: n, buffer} = await this.readFromFile(this.offset, this.offset + this.batchSize);
        this.buf = buffer;

        this.bufSize = n;
        this.offset += n;

        // not reach EOF
        if (n === expectedBufSize) {
            return [true, null];
        }

        if (n > expectedBufSize) {
            // should never happen
            throw new Error("load more data from file than expected")
        }

        if (expectedBufSize > n) {
            this.paddingZeros(expectedBufSize - n);
        }

        return [true, null];
    }

    current(): Uint8Array {
        return this.buf.subarray(0, this.bufSize);
    }
}
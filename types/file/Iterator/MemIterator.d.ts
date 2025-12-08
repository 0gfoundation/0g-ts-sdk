import { Iterator } from './Iterator.js';
import { AbstractFile } from '../AbstractFile.js';
export declare class MemIterator implements Iterator {
    file: AbstractFile;
    buf: Uint8Array;
    bufSize: number;
    fileSize: number;
    paddedSize: number;
    offset: number;
    batchSize: number;
    constructor(file: AbstractFile, offset: number, batch: number, paddedSize: number);
    readFromFile(start: number, end: number): Promise<{
        bytesRead: number;
        buffer: Uint8Array;
    }>;
    clearBuffer(): void;
    paddingZeros(length: number): void;
    next(): Promise<[boolean, Error | null]>;
    current(): Uint8Array;
}
//# sourceMappingURL=MemIterator.d.ts.map
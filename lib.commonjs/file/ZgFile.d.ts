import { FileHandle } from 'node:fs/promises';
import { Iterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
export declare class ZgFile extends AbstractFile {
    fd: FileHandle | null;
    constructor(fd: FileHandle, offset?: number, size?: number, paddedSize?: number);
    static fromNodeFileHandle(fd: FileHandle): Promise<ZgFile>;
    static fromFilePath(path: string): Promise<ZgFile>;
    close(): Promise<void>;
    protected createFragment(offset: number, size: number, paddedSize: number): AbstractFile;
    readFromFile(start: number, end: number): Promise<{
        bytesRead: number;
        buffer: Uint8Array;
    }>;
    iterateWithOffsetAndBatch(offset: number, batch: number, flowPadding: boolean): Iterator;
}
//# sourceMappingURL=ZgFile.d.ts.map
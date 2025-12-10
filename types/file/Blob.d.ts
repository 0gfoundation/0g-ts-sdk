import { Iterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
export declare class Blob extends AbstractFile {
    blob: File | null;
    constructor(blob: File, offset?: number, size?: number, paddedSize?: number);
    protected createFragment(offset: number, size: number, paddedSize: number): AbstractFile;
    readFromFile(start: number, end: number): Promise<{
        bytesRead: number;
        buffer: Uint8Array;
    }>;
    iterateWithOffsetAndBatch(offset: number, batch: number, flowPadding: boolean): Iterator;
}
//# sourceMappingURL=Blob.d.ts.map
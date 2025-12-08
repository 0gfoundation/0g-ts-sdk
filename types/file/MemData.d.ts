import { Iterator } from './Iterator/index.js';
import { AbstractFile } from './AbstractFile.js';
export declare class MemData extends AbstractFile {
    data: ArrayLike<number>;
    constructor(data: ArrayLike<number>, offset?: number, size?: number, paddedSize?: number);
    protected createFragment(offset: number, size: number, paddedSize: number): AbstractFile;
    readFromFile(start: number, end: number): Promise<{
        bytesRead: number;
        buffer: Uint8Array;
    }>;
    iterateWithOffsetAndBatch(offset: number, batch: number, flowPadding: boolean): Iterator;
}
//# sourceMappingURL=MemData.d.ts.map
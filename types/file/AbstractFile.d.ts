import { BytesLike } from 'ethers';
import { MerkleTree } from './MerkleTree.js';
import { SubmissionNodeStruct, SubmissionStruct } from '../contracts/flow/FixedPriceFlow.js';
import { Iterator } from './Iterator/index.js';
export declare abstract class AbstractFile {
    paddedSize_: number;
    offset: number;
    size_: number;
    static segmentRoot(segment: Uint8Array, emptyChunksPadded?: number): string;
    size(): number;
    abstract iterateWithOffsetAndBatch(offset: number, batch: number, flowPadding: boolean): Iterator;
    /**
     * Read data from the file at the given offset relative to this file's offset
     * @param start Start position relative to this file's beginning
     * @param end End position relative to this file's beginning
     * @returns Promise with bytes read and buffer
     */
    abstract readFromFile(start: number, end: number): Promise<{
        bytesRead: number;
        buffer: Uint8Array;
    }>;
    merkleTree(): Promise<[MerkleTree | null, Error | null]>;
    numChunks(): number;
    numSegments(): number;
    paddedSize(): number;
    numSegmentsPadded(): number;
    /**
     * Split file into fragments of specified size
     * @param fragmentSize Size of each fragment in bytes
     * @returns Array of file fragments
     */
    split(fragmentSize: number): AbstractFile[];
    /**
     * Create a fragment of this file with given offset and size
     * Subclasses should implement this method
     */
    protected abstract createFragment(offset: number, size: number, paddedSize: number): AbstractFile;
    createSubmission(tags: BytesLike): Promise<[SubmissionStruct | null, Error | null]>;
    splitNodes(): number[];
    createNode(offset: number, chunks: number): Promise<[SubmissionNodeStruct | null, Error | null]>;
    createSegmentNode(offset: number, batch: number, size: number): Promise<[SubmissionNodeStruct | null, Error | null]>;
}
//# sourceMappingURL=AbstractFile.d.ts.map
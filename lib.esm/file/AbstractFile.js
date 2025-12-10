import { MerkleTree } from './MerkleTree.js';
import { DEFAULT_CHUNK_SIZE, DEFAULT_SEGMENT_SIZE, DEFAULT_SEGMENT_MAX_CHUNKS, EMPTY_CHUNK_HASH, ZERO_HASH, } from '../constant.js';
import { computePaddedSize, numSplits, iteratorPaddedSize } from './utils.js';
export class AbstractFile {
    paddedSize_ = 0;
    offset = 0;
    size_ = 0;
    // constructor() {}
    // split a segment into chunks and compute the root hash
    static segmentRoot(segment, emptyChunksPadded = 0) {
        const tree = new MerkleTree();
        const dataLength = segment.length;
        for (let offset = 0; offset < dataLength; offset += DEFAULT_CHUNK_SIZE) {
            const chunk = segment.subarray(offset, offset + DEFAULT_CHUNK_SIZE);
            tree.addLeaf(chunk);
        }
        if (emptyChunksPadded > 0) {
            for (let i = 0; i < emptyChunksPadded; i++) {
                tree.addLeafByHash(EMPTY_CHUNK_HASH);
            }
        }
        tree.build();
        if (tree.root !== null) {
            return tree.rootHash();
        }
        return ZERO_HASH; // TODO check this
    }
    size() {
        return this.size_;
    }
    async merkleTree() {
        const iter = this.iterateWithOffsetAndBatch(0, DEFAULT_SEGMENT_SIZE, true);
        const tree = new MerkleTree();
        while (true) {
            let [ok, err] = await iter.next();
            if (err != null) {
                return [null, err];
            }
            if (!ok) {
                break;
            }
            const current = iter.current();
            const segRoot = AbstractFile.segmentRoot(current);
            console.log('Segment root at file offset', this.offset, ':', segRoot);
            tree.addLeafByHash(segRoot);
        }
        return [tree.build(), null];
    }
    numChunks() {
        return numSplits(this.size(), DEFAULT_CHUNK_SIZE);
    }
    numSegments() {
        return numSplits(this.size(), DEFAULT_SEGMENT_SIZE);
    }
    paddedSize() {
        return this.paddedSize_;
    }
    numSegmentsPadded() {
        return numSplits(this.paddedSize(), DEFAULT_SEGMENT_SIZE);
    }
    /**
     * Split file into fragments of specified size
     * @param fragmentSize Size of each fragment in bytes
     * @returns Array of file fragments
     */
    split(fragmentSize) {
        const fragments = [];
        for (let offset = this.offset; offset < this.offset + this.size(); offset += fragmentSize) {
            const size = Math.min(this.size() - offset, fragmentSize);
            const fragmentPaddedSize = iteratorPaddedSize(size, true);
            const fragment = this.createFragment(offset, size, fragmentPaddedSize);
            fragments.push(fragment);
        }
        return fragments;
    }
    async createSubmission(tags) {
        const submission = {
            length: this.size(),
            tags: tags,
            nodes: [],
        };
        const nodes = this.splitNodes();
        let offset = 0;
        for (let chunks of nodes) {
            let [node, err] = await this.createNode(offset, chunks);
            if (err != null) {
                return [null, err];
            }
            submission.nodes.push(node);
            offset += chunks * DEFAULT_CHUNK_SIZE;
        }
        return [submission, null];
    }
    splitNodes() {
        let nodes = [];
        let chunks = this.numChunks();
        let [paddedChunks, chunksNextPow2] = computePaddedSize(chunks);
        let nextChunkSize = chunksNextPow2;
        while (paddedChunks > 0) {
            if (paddedChunks >= nextChunkSize) {
                paddedChunks -= nextChunkSize;
                nodes.push(nextChunkSize);
            }
            nextChunkSize /= 2;
        }
        return nodes;
    }
    async createNode(offset, chunks) {
        let batch = chunks;
        if (chunks > DEFAULT_SEGMENT_MAX_CHUNKS) {
            batch = DEFAULT_SEGMENT_MAX_CHUNKS;
        }
        return this.createSegmentNode(offset, DEFAULT_CHUNK_SIZE * batch, DEFAULT_CHUNK_SIZE * chunks);
    }
    async createSegmentNode(offset, batch, size) {
        const iter = this.iterateWithOffsetAndBatch(offset, batch, true);
        const tree = new MerkleTree();
        for (let i = 0; i < size;) {
            let [ok, err] = await iter.next();
            if (err != null) {
                return [null, err];
            }
            if (!ok) {
                break;
            }
            const current = iter.current();
            const segRoot = AbstractFile.segmentRoot(current);
            tree.addLeafByHash(segRoot);
            i += current.length;
        }
        tree.build();
        const numChunks = size / DEFAULT_CHUNK_SIZE;
        const height = Math.log2(numChunks);
        const node = {
            height: height,
            root: tree.rootHash(),
        };
        return [node, null];
    }
}
//# sourceMappingURL=AbstractFile.js.map
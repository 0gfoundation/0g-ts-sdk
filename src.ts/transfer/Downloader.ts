import { DEFAULT_SEGMENT_MAX_CHUNKS, DEFAULT_CHUNK_SIZE } from '../constant.js'
import { GetSplitNum, checkExist } from '../utils.js'
import { StorageNode, Segment, FileInfo } from '../node/index.js'
import { decodeBase64 } from 'ethers'
import { Hash } from '../types.js'
import { getShardConfigs } from './utils.js'
import { ShardConfig } from '../common/index.js'

export class Downloader {
    nodes: StorageNode[]
    shardConfigs: ShardConfig[]
    startSegmentIndex: number
    endSegmentIndex: number

    constructor(nodes: StorageNode[]) {
        this.nodes = nodes
        this.shardConfigs = []
        this.startSegmentIndex = 0
        this.endSegmentIndex = 0
    }

    // ─── File-system download (Node.js only) ─────────────────────────────

    /**
     * Downloads a single file by root hash, writing to `filePath`.
     * Node.js only — uses the `fs` module.
     */
    async download(root: Hash, filePath: string, proof?: boolean): Promise<Error | null>

    /**
     * Downloads multiple files by root hashes, concatenating them into
     * a single file at `filePath`.
     * Node.js only — uses the `fs` module.
     */
    async download(roots: Hash[], filePath: string, proof?: boolean): Promise<Error | null>

    async download(
        rootOrRoots: Hash | Hash[],
        filePath: string,
        proof: boolean = false
    ): Promise<Error | null> {
        if (Array.isArray(rootOrRoots)) {
            return this.downloadFragments(rootOrRoots, filePath, proof)
        } else {
            return this.downloadFile(rootOrRoots, filePath, proof)
        }
    }

    async downloadFile(
        root: Hash,
        filePath: string,
        proof: boolean
    ): Promise<Error | null> {
        const [info, err] = await this.queryFile(root)
        if (err != null || info === null) {
            return new Error(err?.message)
        }
        if (!info.finalized) {
            return new Error('File not finalized')
        }
        if (await checkExist(filePath)) {
            return new Error('Wrong path, provide a file path which does not exist.')
        }

        const shardConfigs = await getShardConfigs(this.nodes)
        if (shardConfigs === null) {
            return new Error('Failed to get shard configs')
        }
        this.shardConfigs = shardConfigs

        return this.downloadFileHelper(filePath, info, proof)
    }

    async downloadFragments(
        roots: string[],
        filename: string,
        withProof: boolean = false
    ): Promise<Error | null> {
        // Dynamic import keeps `fs` out of browser bundles
        const fs = await import(/* webpackIgnore: true */ 'fs')
        const path = await import(/* webpackIgnore: true */ 'path')

        if (await checkExist(filename)) {
            return new Error('Output file already exists. Provide a file path which does not exist.')
        }

        const outputDir = path.dirname(filename)
        if (!fs.existsSync(outputDir)) {
            try {
                fs.mkdirSync(outputDir, { recursive: true })
            } catch (err) {
                return new Error(`Failed to create output directory: ${err}`)
            }
        }

        let outFileHandle: number
        try {
            outFileHandle = fs.openSync(filename, 'w')
        } catch (err) {
            return new Error(`Failed to create output file: ${err}`)
        }

        const tempFiles: string[] = []
        try {
            for (const root of roots) {
                const tempFile = path.join(outputDir, `${root}.temp`)
                tempFiles.push(tempFile)

                const downloadErr = await this.downloadFile(root, tempFile, withProof)
                if (downloadErr != null) {
                    return new Error(`Failed to download file with root ${root}: ${downloadErr.message}`)
                }

                try {
                    const data = fs.readFileSync(tempFile)
                    fs.writeSync(outFileHandle, new Uint8Array(data))
                } catch (err) {
                    return new Error(`Failed to copy content from temp file ${tempFile}: ${err}`)
                }

                try {
                    fs.unlinkSync(tempFile)
                } catch (err) {
                    console.warn(`Warning: failed to delete temp file ${tempFile}: ${err}`)
                }
            }
            return null
        } catch (err) {
            return new Error(`Unexpected error during download fragments: ${err}`)
        } finally {
            try {
                fs.closeSync(outFileHandle!)
            } catch (err) {
                console.warn(`Warning: failed to close output file: ${err}`)
            }
            for (const tempFile of tempFiles) {
                try {
                    if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile)
                } catch (err) {
                    console.warn(`Warning: failed to clean up temp file ${tempFile}: ${err}`)
                }
            }
        }
    }

    // ─── In-memory / browser-safe download ───────────────────────────────

    /**
     * Downloads a single file into a Blob — browser and Node.js safe.
     */
    async downloadToBlob(root: Hash, proof?: boolean): Promise<[Blob, Error | null]>

    /**
     * Downloads multiple files and concatenates them into a single Blob —
     * browser and Node.js safe.
     */
    async downloadToBlob(roots: Hash[], proof?: boolean): Promise<[Blob, Error | null]>

    async downloadToBlob(
        rootOrRoots: Hash | Hash[],
        proof: boolean = false
    ): Promise<[Blob, Error | null]> {
        if (Array.isArray(rootOrRoots)) {
            return this.downloadFragmentsToBlob(rootOrRoots, proof)
        } else {
            return this.downloadFileToBlob(rootOrRoots, proof)
        }
    }

    private async downloadFileToBlob(
        root: Hash,
        proof: boolean
    ): Promise<[Blob, Error | null]> {
        const [info, err] = await this.queryFile(root)
        if (err != null || info === null) {
            return [new Blob(), new Error(err?.message ?? 'Failed to query file')]
        }
        if (!info.finalized) {
            return [new Blob(), new Error('File not finalized')]
        }

        const shardConfigs = await getShardConfigs(this.nodes)
        if (shardConfigs === null) {
            return [new Blob(), new Error('Failed to get shard configs')]
        }
        this.shardConfigs = shardConfigs

        return this.downloadFileHelperToBlob(info, proof)
    }

    private async downloadFileHelperToBlob(
        info: FileInfo,
        proof: boolean
    ): Promise<[Blob, Error | null]> {
        const numChunks = GetSplitNum(info.tx.size, DEFAULT_CHUNK_SIZE)
        this.startSegmentIndex = Math.floor(
            info.tx.startEntryIndex / DEFAULT_SEGMENT_MAX_CHUNKS
        )
        this.endSegmentIndex = Math.floor(
            (info.tx.startEntryIndex + GetSplitNum(info.tx.size, DEFAULT_CHUNK_SIZE) - 1) /
                DEFAULT_SEGMENT_MAX_CHUNKS
        )

        const numTasks = this.endSegmentIndex - this.startSegmentIndex + 1
        const chunks: Uint8Array[] = []

        for (let taskInd = 0; taskInd < numTasks; taskInd++) {
            const [segArray, err] = await this.downloadTask(info, 0, taskInd, numChunks, proof)
            if (err != null) {
                return [new Blob(), err]
            }
            chunks.push(segArray)
        }

        // Cast required: ethers decodeBase64 returns Uint8Array<ArrayBufferLike>
        // which TypeScript won't accept directly as BlobPart[].
        return [new Blob(chunks as unknown as BlobPart[]), null]
    }

    private async downloadFragmentsToBlob(
        roots: Hash[],
        proof: boolean
    ): Promise<[Blob, Error | null]> {
        const blobs: Blob[] = []
        for (const root of roots) {
            const [blob, err] = await this.downloadFileToBlob(root, proof)
            if (err != null) {
                return [new Blob(), err]
            }
            blobs.push(blob)
        }
        return [new Blob(blobs), null]
    }

    // ─── Shared helpers ───────────────────────────────────────────────────

    async queryFile(root: string): Promise<[FileInfo | null, Error | null]> {
        let fileInfo: FileInfo | null = null
        for (const node of this.nodes) {
            const currInfo = await node.getFileInfo(root, true)
            if (currInfo === null) {
                return [null, new Error('File not found on node ' + node.url)]
            } else if (fileInfo === null) {
                fileInfo = currInfo
            }
        }
        return [fileInfo, null]
    }

    // TODO: add proof check
    async downloadTask(
        info: FileInfo,
        segmentOffset: number,
        taskInd: number,
        numChunks: number,
        _proof: boolean
    ): Promise<[Uint8Array, Error | null]> {
        const segmentIndex = segmentOffset + taskInd
        const startIndex = segmentIndex * DEFAULT_SEGMENT_MAX_CHUNKS

        let endIndex = startIndex + DEFAULT_SEGMENT_MAX_CHUNKS
        if (endIndex > numChunks) {
            endIndex = numChunks
        }

        let segment: Segment | null = null
        for (let i = 0; i < this.shardConfigs.length; i++) {
            const nodeIndex = (taskInd + i) % this.shardConfigs.length
            if (
                (this.startSegmentIndex + segmentIndex) %
                    this.shardConfigs[nodeIndex].numShard !==
                this.shardConfigs[nodeIndex].shardId
            ) {
                continue
            }
            segment = await this.nodes[nodeIndex].downloadSegmentByTxSeq(
                info.tx.seq,
                startIndex,
                endIndex
            )
            if (segment === null) {
                continue
            }

            let segArray = decodeBase64(segment)

            if (this.startSegmentIndex + segmentIndex === this.endSegmentIndex) {
                const lastChunkSize = info.tx.size % DEFAULT_CHUNK_SIZE
                if (lastChunkSize > 0) {
                    const paddings = DEFAULT_CHUNK_SIZE - lastChunkSize
                    segArray = segArray.slice(0, segArray.length - paddings)
                }
            }
            return [segArray, null]
        }

        return [
            new Uint8Array(),
            new Error('No storage node holds segment with index ' + segmentIndex),
        ]
    }

    async downloadFileHelper(
        filePath: string,
        info: FileInfo,
        proof: boolean
    ): Promise<Error | null> {
        // Dynamic import keeps `fs` out of browser bundles
        const fs = await import(/* webpackIgnore: true */ 'fs')

        const numChunks = GetSplitNum(info.tx.size, DEFAULT_CHUNK_SIZE)
        this.startSegmentIndex = Math.floor(
            info.tx.startEntryIndex / DEFAULT_SEGMENT_MAX_CHUNKS
        )
        this.endSegmentIndex = Math.floor(
            (info.tx.startEntryIndex +
                GetSplitNum(info.tx.size, DEFAULT_CHUNK_SIZE) -
                1) /
                DEFAULT_SEGMENT_MAX_CHUNKS
        )

        const numTasks = this.endSegmentIndex - this.startSegmentIndex + 1

        for (let taskInd = 0; taskInd < numTasks; taskInd++) {
            const [segArray, err] = await this.downloadTask(
                info,
                0,
                taskInd,
                numChunks,
                proof
            )
            if (err != null) {
                return err
            }
            fs.appendFileSync(filePath, segArray)
        }
        return null
    }
}

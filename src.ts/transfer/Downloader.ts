import fs from 'fs'
import path from 'path'
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

    /**
     * Downloads a single file by root hash
     */
    async download(
        root: Hash,
        filePath: string,
        proof?: boolean
    ): Promise<Error | null>

    /**
     * Downloads multiple files by root hashes and concatenates them
     */
    async download(
        roots: Hash[],
        filePath: string,
        proof?: boolean
    ): Promise<Error | null>

    /**
     * Implementation
     */
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
        var [info, err] = await this.queryFile(root)
        if (err != null || info === null) {
            return new Error(err?.message)
        }
        if (!info.finalized) {
            return new Error('File not finalized')
        }

        if (checkExist(filePath)) {
            return new Error(
                'Wrong path, provide a file path which does not exist.'
            )
        }

        let shardConfigs = await getShardConfigs(this.nodes)
        if (shardConfigs === null) {
            return new Error('Failed to get shard configs')
        }
        this.shardConfigs = shardConfigs

        err = await this.downloadFileHelper(filePath, info, proof)

        return err
    }

    /**
     * Downloads multiple files by their root hashes and concatenates them into a single output file
     * @param roots Array of root hashes to download
     * @param filename Output file path where concatenated data will be written
     * @param withProof Whether to include proof verification during download
     * @returns Promise that resolves to Error if any operation fails, null on success
     */
    async downloadFragments(
        roots: string[],
        filename: string,
        withProof: boolean = false
    ): Promise<Error | null> {
        // Check if output file already exists
        if (checkExist(filename)) {
            return new Error(
                'Output file already exists. Provide a file path which does not exist.'
            )
        }

        // Ensure output directory exists
        const outputDir = path.dirname(filename)
        if (!fs.existsSync(outputDir)) {
            try {
                fs.mkdirSync(outputDir, { recursive: true })
            } catch (err) {
                return new Error(`Failed to create output directory: ${err}`)
            }
        }

        // Create output file stream
        let outFileHandle: number
        try {
            outFileHandle = fs.openSync(filename, 'w')
        } catch (err) {
            return new Error(`Failed to create output file: ${err}`)
        }

        const tempFiles: string[] = []

        try {
            for (const root of roots) {
                // Generate temporary file name
                const tempFile = path.join(outputDir, `${root}.temp`)
                tempFiles.push(tempFile)

                // Download individual file
                const downloadErr = await this.downloadFile(
                    root,
                    tempFile,
                    withProof
                )
                if (downloadErr != null) {
                    return new Error(
                        `Failed to download file with root ${root}: ${downloadErr.message}`
                    )
                }

                // Read and append temp file content to output file
                try {
                    const data = fs.readFileSync(tempFile)
                    fs.writeSync(outFileHandle, new Uint8Array(data))
                } catch (err) {
                    return new Error(
                        `Failed to copy content from temp file ${tempFile}: ${err}`
                    )
                }

                // Clean up temp file immediately after processing
                try {
                    fs.unlinkSync(tempFile)
                } catch (err) {
                    console.warn(
                        `Warning: failed to delete temp file ${tempFile}: ${err}`
                    )
                    // Don't fail the entire operation for cleanup issues
                }
            }

            return null
        } catch (err) {
            return new Error(
                `Unexpected error during download fragments: ${err}`
            )
        } finally {
            // Ensure output file is closed
            try {
                fs.closeSync(outFileHandle)
            } catch (err) {
                console.warn(`Warning: failed to close output file: ${err}`)
            }

            // Clean up any remaining temp files
            for (const tempFile of tempFiles) {
                try {
                    if (fs.existsSync(tempFile)) {
                        fs.unlinkSync(tempFile)
                    }
                } catch (err) {
                    console.warn(
                        `Warning: failed to clean up temp file ${tempFile}: ${err}`
                    )
                }
            }
        }
    }

    async queryFile(root: string): Promise<[FileInfo | null, Error | null]> {
        let fileInfo: FileInfo | null = null
        for (let node of this.nodes) {
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
        proof: boolean
    ): Promise<[Uint8Array, Error | null]> {
        const segmentIndex = segmentOffset + taskInd
        const startIndex = segmentIndex * DEFAULT_SEGMENT_MAX_CHUNKS

        var endIndex = startIndex + DEFAULT_SEGMENT_MAX_CHUNKS
        if (endIndex > numChunks) {
            endIndex = numChunks
        }
        let segment: Segment | null = null
        for (let i = 0; i < this.shardConfigs.length; i++) {
            let nodeIndex = (taskInd + i) % this.shardConfigs.length
            if (
                (this.startSegmentIndex + segmentIndex) %
                    this.shardConfigs[nodeIndex].numShard !=
                this.shardConfigs[nodeIndex].shardId
            ) {
                continue
            }
            // try download from current node
            segment = await this.nodes[nodeIndex].downloadSegmentByTxSeq(
                info.tx.seq,
                startIndex,
                endIndex
            )

            if (segment === null) {
                continue
            }

            var segArray = decodeBase64(segment)

            if (this.startSegmentIndex + segmentIndex == this.endSegmentIndex) {
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
            new Error(
                'No storage node holds segment with index ' + segmentIndex
            ),
        ]
    }

    async downloadFileHelper(
        filePath: string,
        info: FileInfo,
        proof: boolean
    ): Promise<Error | null> {
        const segmentOffset = 0
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
            let [segArray, err] = await this.downloadTask(
                info,
                segmentOffset,
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

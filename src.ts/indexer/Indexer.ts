import { HttpProvider } from 'open-jsonrpc-provider'
import { IpLocation, ShardedNodes, TransactionOptions } from './types.js'
import { selectNodes, ShardedNode } from '../common/index.js'
import {
    UploadOption,
    Uploader,
    Downloader,
    mergeUploadOptions,
} from '../transfer/index.js'
import { StorageNode } from '../node/index.js'
import { RetryOpts } from '../types.js'
import { AbstractFile } from '../file/AbstractFile.js'
import { Signer } from 'ethers'
import { getFlowContract } from '../utils.js'
import * as fs from 'fs'

export class Indexer extends HttpProvider {
    constructor(url: string) {
        super({ url })
    }

    async getShardedNodes(): Promise<ShardedNodes> {
        const res = await super.request({
            method: 'indexer_getShardedNodes',
        })
        return res as ShardedNodes
    }

    async getNodeLocations(): Promise<Map<string, IpLocation>> {
        const res = await super.request({
            method: 'indexer_getNodeLocations',
        })
        return res as Map<string, IpLocation>
    }

    async getFileLocations(rootHash: string): Promise<ShardedNode[]> {
        const res = await super.request({
            method: 'indexer_getFileLocations',
            params: [rootHash],
        })
        return res as ShardedNode[]
    }

    async newUploaderFromIndexerNodes(
        blockchain_rpc: string,
        signer: Signer,
        expectedReplica: number,
        opts?: TransactionOptions
    ): Promise<[Uploader | null, Error | null]> {
        let [clients, err] = await this.selectNodes(expectedReplica)
        if (err != null) {
            return [null, err]
        }

        let status = await clients[0].getStatus()
        if (status == null) {
            return [
                null,
                new Error('failed to get status from the selected node'),
            ]
        }

        console.log('First selected node status :', status)

        let flow = getFlowContract(status.networkIdentity.flowAddress, signer)

        console.log('Selected nodes:', clients)

        let uploader: Uploader = new Uploader(
            clients,
            blockchain_rpc,
            flow,
            opts?.gasPrice,
            opts?.gasLimit
        )
        return [uploader, null]
    }

    async selectNodes(
        expectedReplica: number
    ): Promise<[StorageNode[], Error | null]> {
        let nodes: ShardedNodes = await this.getShardedNodes()
        let [trusted, ok] = selectNodes(nodes.trusted, expectedReplica)
        if (!ok) {
            return [
                [],
                new Error(
                    'cannot select a subset from the returned nodes that meets the replication requirement'
                ),
            ]
        }
        let clients: StorageNode[] = []
        trusted.forEach((node) => {
            let sn = new StorageNode(node.url)
            clients.push(sn)
        })

        return [clients, null]
    }

    async upload(
        file: AbstractFile,
        blockchain_rpc: string,
        signer: Signer,
        uploadOpts?: UploadOption,
        retryOpts?: RetryOpts,
        opts?: TransactionOptions
    ): Promise<
        [
            (
                | { txHash: string; rootHash: string }
                | { txHashes: string[]; rootHashes: string[] }
            ),
            Error | null
        ]
    > {
        console.log(`Starting upload for file of size: ${file.size()} bytes`)

        const mergedOpts = mergeUploadOptions(uploadOpts)

        console.log(`Upload options:`, mergedOpts)

        let [uploader, err] = await this.newUploaderFromIndexerNodes(
            blockchain_rpc,
            signer,
            mergedOpts.expectedReplica,
            opts
        )
        if (err != null || uploader == null) {
            console.error(`Failed to create uploader: ${err?.message}`)
            return [{ txHash: '', rootHash: '' }, err]
        }

        console.log(
            `Using splitable upload (handles both single and fragment cases)`
        )

        // Add debugging info before upload
        console.log(
            `File details - size: ${file.size()}, numSegments: ${file.numSegments()}, numChunks: ${file.numChunks()}`
        )

        const [result, uploadErr] = await uploader.splitableUpload(
            file,
            mergedOpts,
            retryOpts
        )
        if (uploadErr != null) {
            console.error(`Upload failed with error:`, uploadErr.message)
            console.error(`Error stack:`, uploadErr.stack)
            return [{ txHash: '', rootHash: '' }, uploadErr]
        }

        // Check if it's a single file result (array with one element) or multiple fragments
        if (result.txHashes.length === 1 && result.rootHashes.length === 1) {
            console.log(
                `Single file upload completed - returning single result`
            )
            return [
                {
                    txHash: result.txHashes[0],
                    rootHash: result.rootHashes[0],
                },
                null,
            ]
        } else {
            console.log(
                `Fragment upload completed - returning ${result.txHashes.length} fragments`
            )
            return [result, null]
        }
    }

    /**
     * Downloads a single file by root hash
     */
    async download(
        rootHash: string,
        filePath: string,
        proof?: boolean
    ): Promise<Error | null>

    /**
     * Downloads multiple files by root hashes and concatenates them
     */
    async download(
        rootHashes: string[],
        filePath: string,
        proof?: boolean
    ): Promise<Error | null>

    /**
     * Implementation
     */
    async download(
        rootHashOrHashes: string | string[],
        filePath: string,
        proof: boolean = false
    ): Promise<Error | null> {
        console.log(`Starting download to: ${filePath}, proof: ${proof}`)

        if (Array.isArray(rootHashOrHashes)) {
            // Handle multiple files - download fragments sequentially
            console.log(
                `Downloading ${rootHashOrHashes.length} fragments:`,
                rootHashOrHashes
            )

            return await this.downloadFragments(
                rootHashOrHashes,
                filePath,
                proof
            )
        } else {
            // Handle single file
            console.log(
                `Downloading single file with root hash: ${rootHashOrHashes}`
            )

            return await this.downloadSingle(rootHashOrHashes, filePath, proof)
        }
    }

    /**
     * Downloads fragments sequentially to temp files and concatenates them
     */
    private async downloadFragments(
        rootHashes: string[],
        filePath: string,
        proof: boolean
    ): Promise<Error | null> {
        // Create output file
        let outFile: fs.WriteStream
        try {
            outFile = fs.createWriteStream(filePath)
        } catch (err) {
            return new Error(
                `Failed to create output file: ${
                    err instanceof Error ? err.message : String(err)
                }`
            )
        }

        try {
            for (const rootHash of rootHashes) {
                console.log(`Processing fragment: ${rootHash}`)

                // Create temp file for this fragment
                const tempFile = `${rootHash}.temp`

                // Create downloader for this specific root hash
                const [downloader, err] =
                    await this.newDownloaderFromIndexerNodes(rootHash)
                if (err !== null || downloader === null) {
                    outFile.destroy()
                    return new Error(
                        `Failed to create downloader for ${rootHash}: ${err?.message}`
                    )
                }

                // Download to temp file
                const downloadErr = await downloader.download(
                    rootHash,
                    tempFile,
                    proof
                )
                if (downloadErr !== null) {
                    outFile.destroy()
                    return new Error(
                        `Failed to download fragment ${rootHash}: ${downloadErr.message}`
                    )
                }

                // Copy temp file content to output file
                try {
                    const inFile = fs.createReadStream(tempFile)
                    await new Promise<void>((resolve, reject) => {
                        inFile.pipe(outFile, { end: false })
                        inFile.on('end', resolve)
                        inFile.on('error', reject)
                    })
                } catch (err) {
                    outFile.destroy()
                    return new Error(
                        `Failed to copy content from temp file ${tempFile}: ${
                            err instanceof Error ? err.message : String(err)
                        }`
                    )
                }

                // Clean up temp file
                try {
                    fs.unlinkSync(tempFile)
                } catch (err) {
                    console.warn(
                        `Failed to delete temp file ${tempFile}: ${
                            err instanceof Error ? err.message : String(err)
                        }`
                    )
                }
            }

            outFile.end()
            return null
        } catch (err) {
            outFile.destroy()
            return new Error(
                `Fragment download failed: ${
                    err instanceof Error ? err.message : String(err)
                }`
            )
        }
    }

    /**
     * Downloads a single file
     */
    private async downloadSingle(
        rootHash: string,
        filePath: string,
        proof: boolean
    ): Promise<Error | null> {
        const [downloader, err] = await this.newDownloaderFromIndexerNodes(
            rootHash
        )
        if (err !== null || downloader === null) {
            return new Error(`Failed to create downloader: ${err?.message}`)
        }

        return await downloader.download(rootHash, filePath, proof)
    }

    /**
     * Creates a new downloader from indexer nodes for the given root hash
     */
    private async newDownloaderFromIndexerNodes(
        rootHash: string
    ): Promise<[Downloader | null, Error | null]> {
        console.log(`Getting file locations for root hash: ${rootHash}`)
        const locations = await this.getFileLocations(rootHash)
        console.log(
            `Found ${locations.length} locations for ${rootHash}:`,
            locations.map((l) => l.url)
        )

        if (locations.length === 0) {
            console.error(`No locations found for root hash: ${rootHash}`)
            return [
                null,
                new Error(`Failed to get file locations for ${rootHash}`),
            ]
        }

        const clients: StorageNode[] = []
        locations.forEach((node) => {
            const sn = new StorageNode(node.url)
            clients.push(sn)
        })

        console.log(`Created ${clients.length} storage clients for ${rootHash}`)
        const downloader = new Downloader(clients)
        return [downloader, null]
    }
}

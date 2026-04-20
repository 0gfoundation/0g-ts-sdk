import { HttpProvider } from 'open-jsonrpc-provider'
import { IpLocation, ShardedNodes, TransactionOptions } from './types.js'
import { selectNodes, SelectMethod, ShardedNode } from '../common/index.js'
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
// NOTE: `fs` is intentionally NOT imported at the top level so that this
// module is safe to bundle for browser environments.  The two methods that
// actually need `fs` (`downloadFragments`, `downloadSingle`) import it
// dynamically at call time.

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

    // ─── Node selection ───────────────────────────────────────────────────

    /**
     * Select `expectedReplica` complete sharding sets from the indexer's
     * trusted nodes and return them as StorageNode clients.
     *
     * @param expectedReplica  Number of full replicas required.
     * @param method           Node ordering before selection (default 'min').
     */
    async selectNodes(
        expectedReplica: number,
        method: SelectMethod = 'min'
    ): Promise<[StorageNode[], Error | null]> {
        const nodes: ShardedNodes = await this.getShardedNodes()
        const [trusted, ok] = selectNodes(nodes.trusted, expectedReplica, method)
        if (!ok) {
            return [
                [],
                new Error(
                    'cannot select a subset from the returned nodes that meets the replication requirement'
                ),
            ]
        }
        const clients: StorageNode[] = trusted.map((node) => new StorageNode(node.url))
        return [clients, null]
    }

    // ─── Upload ───────────────────────────────────────────────────────────

    async newUploaderFromIndexerNodes(
        blockchain_rpc: string,
        signer: Signer,
        expectedReplica: number,
        opts?: TransactionOptions
    ): Promise<[Uploader | null, Error | null]> {
        const [clients, err] = await this.selectNodes(expectedReplica, 'min')
        if (err != null) {
            return [null, err]
        }

        const status = await clients[0].getStatus()
        if (status == null) {
            return [null, new Error('failed to get status from the selected node')]
        }

        console.log('First selected node status :', status)

        const flow = getFlowContract(status.networkIdentity.flowAddress, signer)

        console.log('Selected nodes:', clients)

        const uploader: Uploader = new Uploader(
            clients,
            blockchain_rpc,
            flow,
            opts?.gasPrice,
            opts?.gasLimit
        )
        return [uploader, null]
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

        const [uploader, err] = await this.newUploaderFromIndexerNodes(
            blockchain_rpc,
            signer,
            mergedOpts.expectedReplica,
            opts
        )
        if (err != null || uploader == null) {
            console.error(`Failed to create uploader: ${err?.message}`)
            return [{ txHash: '', rootHash: '' }, err]
        }

        console.log(`Using splitable upload (handles both single and fragment cases)`)
        console.log(
            `File details - size: ${file.size()}, numSegments: ${file.numSegments()}, numChunks: ${file.numChunks()}`
        )

        const [result, uploadErr] = await uploader.splitableUpload(file, mergedOpts, retryOpts)
        if (uploadErr != null) {
            console.error(`Upload failed with error:`, uploadErr.message)
            console.error(`Error stack:`, uploadErr.stack)
            return [{ txHash: '', rootHash: '' }, uploadErr]
        }

        if (result.txHashes.length === 1 && result.rootHashes.length === 1) {
            console.log(`Single file upload completed - returning single result`)
            return [{ txHash: result.txHashes[0], rootHash: result.rootHashes[0] }, null]
        } else {
            console.log(`Fragment upload completed - returning ${result.txHashes.length} fragments`)
            return [result, null]
        }
    }

    // ─── File-system download (Node.js only) ─────────────────────────────

    /**
     * Downloads a single file by root hash, writing to `filePath`.
     * Node.js only — uses the `fs` module.
     */
    async download(rootHash: string, filePath: string, proof?: boolean): Promise<Error | null>

    /**
     * Downloads multiple files by root hashes and concatenates them.
     * Node.js only — uses the `fs` module.
     */
    async download(rootHashes: string[], filePath: string, proof?: boolean): Promise<Error | null>

    async download(
        rootHashOrHashes: string | string[],
        filePath: string,
        proof: boolean = false
    ): Promise<Error | null> {
        console.log(`Starting download to: ${filePath}, proof: ${proof}`)

        if (Array.isArray(rootHashOrHashes)) {
            console.log(`Downloading ${rootHashOrHashes.length} fragments:`, rootHashOrHashes)
            return await this.downloadFragments(rootHashOrHashes, filePath, proof)
        } else {
            console.log(`Downloading single file with root hash: ${rootHashOrHashes}`)
            return await this.downloadSingle(rootHashOrHashes, filePath, proof)
        }
    }

    private async downloadFragments(
        rootHashes: string[],
        filePath: string,
        proof: boolean
    ): Promise<Error | null> {
        // Dynamic import — keeps `fs` out of browser bundles
        const fs = await import('fs')

        let outFile: import('fs').WriteStream
        try {
            outFile = fs.createWriteStream(filePath)
        } catch (err) {
            return new Error(
                `Failed to create output file: ${err instanceof Error ? err.message : String(err)}`
            )
        }

        try {
            for (const rootHash of rootHashes) {
                console.log(`Processing fragment: ${rootHash}`)

                const tempFile = `${rootHash}.temp`
                const [downloader, err] = await this.newDownloaderFromIndexerNodes(rootHash)
                if (err !== null || downloader === null) {
                    outFile.destroy()
                    return new Error(`Failed to create downloader for ${rootHash}: ${err?.message}`)
                }

                const downloadErr = await downloader.download(rootHash, tempFile, proof)
                if (downloadErr !== null) {
                    outFile.destroy()
                    return new Error(`Failed to download fragment ${rootHash}: ${downloadErr.message}`)
                }

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
                `Fragment download failed: ${err instanceof Error ? err.message : String(err)}`
            )
        }
    }

    private async downloadSingle(
        rootHash: string,
        filePath: string,
        proof: boolean
    ): Promise<Error | null> {
        const [downloader, err] = await this.newDownloaderFromIndexerNodes(rootHash)
        if (err !== null || downloader === null) {
            return new Error(`Failed to create downloader: ${err?.message}`)
        }
        return await downloader.download(rootHash, filePath, proof)
    }

    // ─── In-memory / browser-safe download ───────────────────────────────

    /**
     * Downloads a single file into a Blob — browser and Node.js safe.
     * Fetches file locations from the indexer and selects nodes with
     * the 'random' method for load balancing.
     */
    async downloadToBlob(rootHash: string, proof?: boolean): Promise<[Blob, Error | null]>

    /**
     * Downloads multiple files and concatenates them into a single Blob —
     * browser and Node.js safe.
     */
    async downloadToBlob(rootHashes: string[], proof?: boolean): Promise<[Blob, Error | null]>

    async downloadToBlob(
        rootHashOrHashes: string | string[],
        proof: boolean = false
    ): Promise<[Blob, Error | null]> {
        if (Array.isArray(rootHashOrHashes)) {
            const blobs: Blob[] = []
            for (const rootHash of rootHashOrHashes) {
                const [blob, err] = await this.downloadSingleToBlob(rootHash, proof)
                if (err !== null) {
                    return [new Blob(), err]
                }
                blobs.push(blob)
            }
            return [new Blob(blobs), null]
        } else {
            return this.downloadSingleToBlob(rootHashOrHashes, proof)
        }
    }

    private async downloadSingleToBlob(
        rootHash: string,
        proof: boolean
    ): Promise<[Blob, Error | null]> {
        const [downloader, err] = await this.newDownloaderFromIndexerNodes(rootHash)
        if (err !== null || downloader === null) {
            return [new Blob(), new Error(`Failed to create downloader: ${err?.message}`)]
        }
        return downloader.downloadToBlob(rootHash, proof)
    }

    // ─── Internal helpers ─────────────────────────────────────────────────

    /**
     * Creates a Downloader whose node list is the minimal covering set for
     * `rootHash`, selected with the 'random' method for load balancing.
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
            return [null, new Error(`No locations found for root hash: ${rootHash}`)]
        }

        // Pick one complete covering set, shuffled for load balancing
        const [selected, ok] = selectNodes(locations, 1, 'random')
        if (!ok) {
            return [
                null,
                new Error(`Cannot form a complete shard covering set for ${rootHash}`),
            ]
        }

        console.log(
            `Selected ${selected.length} of ${locations.length} nodes for ${rootHash}`
        )

        const clients = selected.map((node) => new StorageNode(node.url))
        return [new Downloader(clients), null]
    }
}

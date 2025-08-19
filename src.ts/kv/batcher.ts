import { StreamDataBuilder } from './builder.js'
import { FixedPriceFlow } from '../contracts/flow/index.js'
import { StorageNode } from '../node/index.js'
import { MemData } from '../file/index.js'
import {
    defaultUploadOption,
    Uploader,
    UploadOption,
} from '../transfer/index.js'

export class Batcher {
    streamDataBuilder: StreamDataBuilder
    clients: StorageNode[]
    flow: FixedPriceFlow
    blockchainRpc: string

    constructor(
        version: number,
        clients: StorageNode[],
        flow: FixedPriceFlow,
        provider: string
    ) {
        this.streamDataBuilder = new StreamDataBuilder(version)
        this.clients = clients
        this.flow = flow
        this.blockchainRpc = provider
    }

    async exec(
        opts?: UploadOption
    ): Promise<[{ txHash: string; rootHash: string }, Error | null]> {
        // build stream data
        const streamData = this.streamDataBuilder.build()
        const encoded = streamData.encode()

        const data = new MemData(encoded)

        const uploader = new Uploader(
            this.clients,
            this.blockchainRpc,
            this.flow
        )

        if (opts === undefined) {
            opts = defaultUploadOption
        }
        opts.tags = this.streamDataBuilder.buildTags()

        return await uploader.uploadFile(data, opts)
    }
}

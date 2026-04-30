import { BytesLike } from '@ethersproject/bytes'
import { KeyValue } from '../node/index.js'
import { KvClient } from './client.js'

export class KvIterator {
    // client is the client to use for requests.
    client: KvClient
    // streamId is the stream ID.
    streamId: string
    // version is the version of the stream.
    version: number | undefined
    // currentPair is the current key-value pair.
    currentPair: KeyValue | undefined

    // NewIterator creates an iterator.
    constructor(client: KvClient, streamId: string, version?: number) {
        this.client = client
        this.streamId = streamId
        this.version = version
    }

    // Valid check if current position is exist
    valid(): boolean {
        return this.currentPair !== undefined
    }

    getCurrentPair(): KeyValue | undefined {
        return this.currentPair
    }

    async move(kv: KeyValue): Promise<Error | null> {
        if (kv === null) {
            this.currentPair = undefined
            return null
        }
        // The RPC returns `kv.key` as a base64-encoded string (the
        // server's wire format) despite its `Bytes` type. Decode once
        // here so `currentPair.key` is honest raw bytes for both
        // downstream client calls and external consumers.
        const keyBytes = Buffer.from(kv.key as unknown as string, 'base64')
        let value = await this.client.getValue(
            this.streamId,
            keyBytes,
            kv.version
        )
        if (value === null) {
            return new Error('errValueNotFound')
        }
        this.currentPair = {
            key: keyBytes,
            data: value.data,
            size: value.size,
            version: kv.version,
        }
        return null
    }

    async seekBefore(key: BytesLike): Promise<Error | null> {
        let kv = await this.client.getPrev(
            this.streamId,
            key,
            0,
            0,
            true,
            this.version
        )
        return this.move(kv)
    }

    async seekAfter(key: BytesLike): Promise<Error | null> {
        let kv = await this.client.getNext(
            this.streamId,
            key,
            0,
            0,
            true,
            this.version
        )
        return this.move(kv)
    }

    async seekToFirst(): Promise<Error | null> {
        let kv = await this.client.getFirst(this.streamId, 0, 0, this.version)
        return this.move(kv)
    }

    async seekToLast(): Promise<Error | null> {
        let kv = await this.client.getLast(this.streamId, 0, 0, this.version)
        return this.move(kv)
    }

    async next(): Promise<Error | null> {
        if (!this.valid()) {
            return new Error('errIteratorInvalid')
        }
        let kv = await this.client.getNext(
            this.streamId,
            this.currentPair!.key,
            0,
            0,
            false,
            this.version
        )
        return this.move(kv)
    }

    async prev(): Promise<Error | null> {
        if (!this.valid()) {
            return new Error('errIteratorInvalid')
        }
        let kv = await this.client.getPrev(
            this.streamId,
            this.currentPair!.key,
            0,
            0,
            false,
            this.version
        )
        return this.move(kv)
    }
}

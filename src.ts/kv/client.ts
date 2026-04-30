import { BytesLike } from '@ethersproject/bytes'
import { KeyValue, StorageKv, Value } from '../node/index.js'
import { KvIterator } from './iterator.js'
import { MAX_QUERY_SIZE } from './constants.js'

export class KvClient {
    inner: StorageKv

    constructor(rpc: string) {
        const client = new StorageKv(rpc)
        this.inner = client
    }

    newIterator(streamId: string, version?: number): KvIterator {
        return new KvIterator(this, streamId, version)
    }

    async getValue(
        streamId: string,
        key: BytesLike,
        version?: number
    ): Promise<Value | null> {
        let val: Value = {
            data: '',
            size: 0,
            version: version || 0,
        }

        while (true) {
            const seg = await this.inner.getValue(
                streamId,
                key,
                val.data.length,
                MAX_QUERY_SIZE,
                version
            )
            if (seg === undefined) {
                return null
            }

            if (val.version === Number.MAX_SAFE_INTEGER) {
                val.version = seg.version
            } else if (val.version !== seg.version) {
                val.version = seg.version
                val.data = ''
            }
            val.size = seg.size
            const segData = Buffer.from(seg.data, 'base64')
            const valData = Buffer.from(val.data, 'base64')
            val.data = Buffer.concat([valData, segData]).toString('base64')

            if (seg.size == segData.length + valData.length) {
                return val
            }
        }
    }

    async get(
        streamId: string,
        key: BytesLike,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<Value> {
        return this.inner.getValue(streamId, key, startIndex, length, version)
    }

    async getNext(
        streamId: string,
        key: BytesLike,
        startIndex: number,
        length: number,
        inclusive: boolean,
        version?: number
    ): Promise<KeyValue> {
        return this.inner.getNext(
            streamId,
            key,
            startIndex,
            length,
            inclusive,
            version
        )
    }

    async getPrev(
        streamId: string,
        key: BytesLike,
        startIndex: number,
        length: number,
        inclusive: boolean,
        version?: number
    ): Promise<KeyValue> {
        return this.inner.getPrev(
            streamId,
            key,
            startIndex,
            length,
            inclusive,
            version
        )
    }

    async getFirst(
        streamId: string,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<KeyValue> {
        return this.inner.getFirst(streamId, startIndex, length, version)
    }

    async getLast(
        streamId: string,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<KeyValue> {
        return this.inner.getLast(streamId, startIndex, length, version)
    }

    async getTransactionResult(txSeq: number): Promise<string> {
        return this.inner.getTransactionResult(txSeq)
    }

    async getHoldingStreamIds(): Promise<string[]> {
        return this.inner.getHoldingStreamIds()
    }

    async hasWritePermission(
        account: string,
        streamId: string,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        return this.inner.hasWritePermission(account, streamId, key, version)
    }

    async isAdmin(
        account: string,
        streamId: string,
        version?: number
    ): Promise<boolean> {
        return this.inner.isAdmin(account, streamId, version)
    }

    async isSpecialKey(
        streamId: string,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        return this.inner.isSpecialKey(streamId, key, version)
    }

    async isWriterOfKey(
        account: string,
        streamId: string,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        return this.inner.isWriterOfKey(account, streamId, key, version)
    }

    async isWriterOfStream(
        account: string,
        streamId: string,
        version?: number
    ): Promise<boolean> {
        return this.inner.isWriterOfStream(account, streamId, version)
    }
}

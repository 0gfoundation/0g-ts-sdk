import { HttpProvider } from 'open-jsonrpc-provider'
import { BytesLike, hexlify } from '@ethersproject/bytes'
import { KeyValue, Value } from './types'
import { Hash } from '../types'

export class StorageKv extends HttpProvider {
    constructor(url: string) {
        super({ url })
    }

    async getValue(
        streamId: Hash,
        key: BytesLike,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<Value> {
        let params: any = [streamId, hexlify(key), startIndex, length]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_getValue',
            params: params,
        })

        return res as Value
    }

    async getNext(
        streamId: Hash,
        key: BytesLike,
        startIndex: number,
        length: number,
        inclusive: boolean,
        version?: number
    ): Promise<KeyValue> {
        let params: any = [
            streamId,
            hexlify(key),
            startIndex,
            length,
            inclusive,
        ]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_getNext',
            params: params,
        })

        return res as KeyValue
    }

    async getPrev(
        streamId: Hash,
        key: BytesLike,
        startIndex: number,
        length: number,
        inclusive: boolean,
        version?: number
    ): Promise<KeyValue> {
        let params: any = [
            streamId,
            hexlify(key),
            startIndex,
            length,
            inclusive,
        ]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_getPrev',
            params: params,
        })

        return res as KeyValue
    }

    async getFirst(
        streamId: Hash,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<KeyValue> {
        let params = [streamId, startIndex, length]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_getFirst',
            params: params,
        })

        return res as KeyValue
    }

    async getLast(
        streamId: Hash,
        startIndex: number,
        length: number,
        version?: number
    ): Promise<KeyValue> {
        let params = [streamId, startIndex, length]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_getLast',
            params: params,
        })

        return res as KeyValue
    }

    async getTransactionResult(txSeq: number): Promise<string> {
        const res = await super.request({
            method: 'kv_getTransactionResult',
            params: [txSeq.toString()],
        })
        return res as string
    }

    async getHoldingStreamIds(): Promise<Hash[]> {
        const res = await super.request({
            method: 'kv_getHoldingStreamIds',
        })
        return res as Hash[]
    }

    async hasWritePermission(
        account: Hash,
        streamId: Hash,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        let params: any = [account, streamId, hexlify(key)]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_hasWritePermission',
            params: params,
        })
        return res as boolean
    }

    async isAdmin(
        account: Hash,
        streamId: Hash,
        version?: number
    ): Promise<boolean> {
        let params: any = [account, streamId]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_IsAdmin',
            params: params,
        })

        return res as boolean
    }

    async isSpecialKey(
        stremId: Hash,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        let params: any = [stremId, hexlify(key)]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_isSpecialKey',
            params: params,
        })
        return res as boolean
    }

    async isWriterOfKey(
        account: Hash,
        streamId: Hash,
        key: BytesLike,
        version?: number
    ): Promise<boolean> {
        let params: any = [account, streamId, hexlify(key)]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_isWriterOfKey',
            params: params,
        })

        return res as boolean
    }

    async isWriterOfStream(
        account: Hash,
        streamId: Hash,
        version?: number
    ): Promise<boolean> {
        let params: any = [account, streamId]
        if (version !== undefined) {
            params.push(version)
        }

        const res = await super.request({
            method: 'kv_isWriterOfStream',
            params: params,
        })

        return res as boolean
    }
}

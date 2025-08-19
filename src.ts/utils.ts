import { ContractTransactionReceipt, ethers, Signer } from 'ethers'
import { FixedPriceFlow__factory } from './contracts/flow/index.js'
import { FixedPrice__factory } from './contracts/market/index.js'
import fs from 'fs'
import path from 'path'
import { ContractRunner } from 'ethers'
import { BaseContract } from 'ethers'
import {
    DEFAULT_CHUNK_SIZE,
    DEFAULT_SEGMENT_MAX_CHUNKS,
    TIMEOUT_MS,
} from './constant.js'
import { RetryOpts } from './types.js'
import { TransactionReceipt } from 'ethers'

export function getFlowContract(address: string, signer: Signer) {
    return FixedPriceFlow__factory.connect(address, signer)
}

export function getMarketContract(address: string, runner: ContractRunner) {
    return FixedPrice__factory.connect(address, runner)
}

export const delay = (ms: number) => new Promise((res) => setTimeout(res, ms))

export function checkExist(inputPath: string): boolean {
    const dirName = path.dirname(inputPath)
    if (!fs.existsSync(dirName)) {
        return true
    }

    if (fs.existsSync(inputPath) && fs.lstatSync(inputPath).isDirectory()) {
        return true
    }
    // Check if the directory exists and the file does not exist
    if (!fs.existsSync(inputPath)) {
        return false
    }

    return true
}

export function GetSplitNum(total: number, unit: number): number {
    return Math.floor((total - 1) / unit + 1)
}

/**
 * Calculates the start and end segment indices for a file,
 * given the file's start chunk index and file size.
 *
 * @param startChunkIndex - the starting chunk index (integer)
 * @param fileSize - the file size (number of chunks, as an integer)
 * @returns a tuple [startSegmentIndex, endSegmentIndex]
 */
export function SegmentRange(
    startChunkIndex: number,
    fileSize: number
): [number, number] {
    // Calculate total number of chunks for the file
    const totalChunks = GetSplitNum(fileSize, DEFAULT_CHUNK_SIZE)

    // Calculate the starting segment index using integer division
    const startSegmentIndex = Math.floor(
        startChunkIndex / DEFAULT_SEGMENT_MAX_CHUNKS
    )

    // Calculate the ending chunk index and then the segment index
    const endChunkIndex = startChunkIndex + totalChunks - 1
    const endSegmentIndex = Math.floor(
        endChunkIndex / DEFAULT_SEGMENT_MAX_CHUNKS
    )

    return [startSegmentIndex, endSegmentIndex]
}

export async function txWithGasAdjustment(
    contract: BaseContract,
    provider: ethers.JsonRpcProvider,
    method: string,
    params: unknown[],
    txOpts: { value: bigint; gasPrice?: bigint; gasLimit?: bigint },
    retryOpts?: RetryOpts
): Promise<[TransactionReceipt | null, Error | null]> {
    let current_gas_price = txOpts.gasPrice! // gas price is required in txOpts
    let maxGasPrice = current_gas_price
    if (retryOpts !== undefined && retryOpts.MaxGasPrice > 0) {
        maxGasPrice = BigInt(retryOpts.MaxGasPrice)
    }

    let err: Error | null = null

    while (current_gas_price <= maxGasPrice) {
        console.log(`Sending transaction with gas price ${current_gas_price}`)
        txOpts.gasPrice = current_gas_price
        try {
            let resp = await contract
                .getFunction(method)


                .send(...params, txOpts)
            const tx = (await Promise.race([
                resp.wait(),
                new Promise((_, reject) =>
                    setTimeout(
                        () => reject(new Error('Transaction timeout')),
                        TIMEOUT_MS
                    )
                ),
            ])) as ContractTransactionReceipt | null

            if (tx === null) {
                throw new Error('Send transaction timeout')
            }

            console.log(tx)

            let receipt = await waitForReceipt(provider, tx.hash, retryOpts)
            if (receipt === null) {
                throw new Error('Get transaction receipt timeout')
            }

            return [receipt, null]
        } catch (e) {
            err = e as Error
            if (e instanceof Error && e.message.includes('timeout')) {
                console.log(
                    `Failed to send transaction with gas price ${current_gas_price}, with error ${e}, retrying with higher gas price`
                )
                current_gas_price =
                    (BigInt(11) * BigInt(current_gas_price)) / BigInt(10)

                await delay(1000)
            } else {
                return [null, err]
            }
        }
    }
    return [null, err]
}

async function waitForReceipt(
    provider: ethers.Provider,
    txHash: string,
    opts?: RetryOpts
): Promise<ethers.TransactionReceipt | null> {
    var receipt: ethers.TransactionReceipt | null = null

    if (opts === undefined || opts === null) {
        opts = { Retries: 10, Interval: 5, MaxGasPrice: 0, TooManyDataRetries: 3 }
    }
    if (opts.Retries === undefined || opts.Retries === 0) {
        opts.Retries = 10
    }

    if (opts.Interval === undefined || opts.Interval === 0) {
        opts.Interval = 5
    }

    let nTries = 0

    while (nTries < opts.Retries) {
        await delay(opts.Interval * 1000)
        receipt = await provider.getTransactionReceipt(txHash)

        if (receipt !== null && receipt.status == 1) {
            return receipt
        }
        
        nTries++
    }

    return null
}

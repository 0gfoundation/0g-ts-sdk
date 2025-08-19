import { FixedPriceFlow__factory } from './contracts/flow/index.js';
import { FixedPrice__factory } from './contracts/market/index.js';
import fs from 'fs';
import path from 'path';
import { DEFAULT_CHUNK_SIZE, DEFAULT_SEGMENT_MAX_CHUNKS } from './constant.js';
export function getFlowContract(address, signer) {
    return FixedPriceFlow__factory.connect(address, signer);
}
export function getMarketContract(address, runner) {
    return FixedPrice__factory.connect(address, runner);
}
export const delay = (ms) => new Promise((res) => setTimeout(res, ms));
export function checkExist(inputPath) {
    const dirName = path.dirname(inputPath);
    if (!fs.existsSync(dirName)) {
        return true;
    }
    if (fs.existsSync(inputPath) && fs.lstatSync(inputPath).isDirectory()) {
        return true;
    }
    // Check if the directory exists and the file does not exist
    if (!fs.existsSync(inputPath)) {
        return false;
    }
    return true;
}
export function GetSplitNum(total, unit) {
    return Math.floor((total - 1) / unit + 1);
}
/**
 * Calculates the start and end segment indices for a file,
 * given the file's start chunk index and file size.
 *
 * @param startChunkIndex - the starting chunk index (integer)
 * @param fileSize - the file size (number of chunks, as an integer)
 * @returns a tuple [startSegmentIndex, endSegmentIndex]
 */
export function SegmentRange(startChunkIndex, fileSize) {
    // Calculate total number of chunks for the file
    const totalChunks = GetSplitNum(fileSize, DEFAULT_CHUNK_SIZE);
    // Calculate the starting segment index using integer division
    const startSegmentIndex = Math.floor(startChunkIndex / DEFAULT_SEGMENT_MAX_CHUNKS);
    // Calculate the ending chunk index and then the segment index
    const endChunkIndex = startChunkIndex + totalChunks - 1;
    const endSegmentIndex = Math.floor(endChunkIndex / DEFAULT_SEGMENT_MAX_CHUNKS);
    return [startSegmentIndex, endSegmentIndex];
}
export async function txWithGasAdjustment(contract, provider, method, params, txOpts, retryOpts) {
    let current_gas_price = txOpts.gasPrice; // gas price is required in txOpts
    let maxGasPrice = current_gas_price;
    if (retryOpts !== undefined && retryOpts.MaxGasPrice > 0) {
        maxGasPrice = BigInt(retryOpts.MaxGasPrice);
    }
    let err = null;
    while (current_gas_price <= maxGasPrice) {
        console.log(`Sending transaction with gas price ${current_gas_price}`);
        txOpts.gasPrice = current_gas_price;
        try {
            let resp = await contract
                .getFunction(method)
                .send(...params, txOpts);
            const tx = await resp.wait();
            if (tx === null) {
                throw new Error('Send transaction timeout');
            }
            let receipt = await waitForReceipt(provider, tx.hash, retryOpts);
            if (receipt === null) {
                throw new Error('Get transaction receipt timeout');
            }
            return [receipt, null];
        }
        catch (e) {
            err = e;
            if (e instanceof Error && e.message.includes('timeout')) {
                console.log(`Failed to send transaction with gas price ${current_gas_price}, with error ${e}, retrying with higher gas price`);
                current_gas_price =
                    (BigInt(11) * BigInt(current_gas_price)) / BigInt(10);
                await delay(1000);
            }
            else {
                return [null, err];
            }
        }
    }
    return [null, err];
}
async function waitForReceipt(provider, txHash, opts) {
    var receipt = null;
    if (opts === undefined) {
        opts = { Retries: 10, Interval: 5, MaxGasPrice: 0 };
    }
    if (opts.Retries === undefined || opts.Retries === 0) {
        opts.Retries = 10;
    }
    if (opts.Interval === undefined || opts.Interval === 0) {
        opts.Interval = 5;
    }
    let nTries = 0;
    while (nTries < opts.Retries) {
        receipt = await provider.getTransactionReceipt(txHash);
        if (receipt !== null && receipt.status == 1) {
            return receipt;
        }
        await delay(opts.Interval * 1000);
        nTries++;
    }
    return null;
}
//# sourceMappingURL=utils.js.map
import { ethers, Signer } from 'ethers';
import { ContractRunner } from 'ethers';
import { BaseContract } from 'ethers';
import { RetryOpts } from './types.js';
import { TransactionReceipt } from 'ethers';
export declare function getFlowContract(address: string, signer: Signer): import("./contracts/flow/FixedPriceFlow.js").FixedPriceFlow;
export declare function getMarketContract(address: string, runner: ContractRunner): import("./contracts/market/FixedPrice.js").FixedPrice;
export declare const delay: (ms: number) => Promise<unknown>;
export declare function checkExist(inputPath: string): boolean;
export declare function GetSplitNum(total: number, unit: number): number;
/**
 * Calculates the start and end segment indices for a file,
 * given the file's start chunk index and file size.
 *
 * @param startChunkIndex - the starting chunk index (integer)
 * @param fileSize - the file size (number of chunks, as an integer)
 * @returns a tuple [startSegmentIndex, endSegmentIndex]
 */
export declare function SegmentRange(startChunkIndex: number, fileSize: number): [number, number];
export declare function txWithGasAdjustment(contract: BaseContract, provider: ethers.JsonRpcProvider, method: string, params: unknown[], txOpts: {
    value: bigint;
    gasPrice?: bigint;
    gasLimit?: bigint;
}, retryOpts?: RetryOpts): Promise<[TransactionReceipt | null, Error | null]>;
//# sourceMappingURL=utils.d.ts.map
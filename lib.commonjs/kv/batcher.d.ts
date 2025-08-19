import { StreamDataBuilder } from './builder.js';
import { FixedPriceFlow } from '../contracts/flow/index.js';
import { StorageNode } from '../node/index.js';
import { UploadOption } from '../transfer/index.js';
export declare class Batcher {
    streamDataBuilder: StreamDataBuilder;
    clients: StorageNode[];
    flow: FixedPriceFlow;
    blockchainRpc: string;
    constructor(version: number, clients: StorageNode[], flow: FixedPriceFlow, provider: string);
    exec(opts?: UploadOption): Promise<[{
        txHash: string;
        rootHash: string;
    }, Error | null]>;
}
//# sourceMappingURL=batcher.d.ts.map
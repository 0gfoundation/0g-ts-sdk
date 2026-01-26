import { ShardConfig } from '../common/index.js'
import { SubmissionStruct } from '../contracts/flow/FixedPriceFlow.js'
import { StorageNode, isValidConfig } from '../node/index.js'

export async function getShardConfigs(
    nodes: StorageNode[]
): Promise<ShardConfig[] | null> {
    var configs: ShardConfig[] = []
    for (const cNode of nodes) {
        const cConfig: ShardConfig = await cNode.getShardConfig()
        if (!isValidConfig(cConfig)) {
            return null
        }
        configs.push(cConfig)
    }

    return configs
}

export function calculatePrice(
    submission: SubmissionStruct,
    pricePerSector: bigint
): bigint {
    let sectors: number = 0
    for (const node of submission.data.nodes) {
        sectors += 1 << Number(node.height.toString())
    }

    return BigInt(sectors) * pricePerSector
}

import { insert, SegmentTreeNode } from './segment_tree.js'
import { ShardConfig, ShardedNode } from './types.js'

export * from './types.js'
export * from './segment_tree.js'

/**
 * Controls the order in which candidate nodes are evaluated by selectNodes.
 *
 * 'min'    – sort by numShard ascending, then shardId ascending (default).
 *            Prefers coarser-grained nodes; typically yields fewer selected
 *            nodes. Good for upload.
 * 'max'    – sort by numShard descending, then shardId ascending.
 *            Prefers finer-grained nodes first.
 * 'random' – shuffle before selection.
 *            Spreads load across replicas. Recommended for download.
 */
export type SelectMethod = 'min' | 'max' | 'random'

/**
 * Select a minimal set of nodes that provides `expectedReplica` complete,
 * non-overlapping sharding sets.
 *
 * A node with (shardId=K, numShard=N) holds segments where
 * globalSegmentIndex % N === K.  expectedReplica=R means R full copies
 * of the file are available in the returned set.
 *
 * The input array is never mutated.
 * Returns [selectedNodes, true] on success, [[], false] when coverage
 * cannot be satisfied.
 */
export function selectNodes(
    nodes: ShardedNode[],
    expectedReplica: number,
    method: SelectMethod = 'min'
): [ShardedNode[], boolean] {
    if (expectedReplica === 0) {
        return [[], false]
    }

    const sorted = [...nodes] // never mutate the caller's array

    switch (method) {
        case 'random':
            for (let i = sorted.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1))
                ;[sorted[i], sorted[j]] = [sorted[j], sorted[i]]
            }
            break
        case 'max':
            sorted.sort((a, b) => {
                if (a.config.numShard !== b.config.numShard) {
                    return b.config.numShard - a.config.numShard
                }
                return a.config.shardId - b.config.shardId
            })
            break
        case 'min':
        default:
            sorted.sort((a, b) => {
                if (a.config.numShard !== b.config.numShard) {
                    return a.config.numShard - b.config.numShard
                }
                return a.config.shardId - b.config.shardId
            })
            break
    }

    const root: SegmentTreeNode = {
        childs: null,
        numShard: 1,
        replica: 0,
        lazyTags: 0,
    }

    const selectedNodes: ShardedNode[] = []
    for (let i = 0; i < sorted.length; i += 1) {
        const node = sorted[i]
        if (
            insert(
                root,
                node.config.numShard,
                node.config.shardId,
                expectedReplica
            )
        ) {
            selectedNodes.push(node)
        }
        if (root.replica >= expectedReplica) {
            return [selectedNodes, true]
        }
    }

    return [[], false]
}

/**
 * Given a covering set returned by selectNodes, return the node responsible
 * for the segment at `globalSegIdx`.
 *
 * A node (shardId=K, numShard=N) is responsible when globalSegIdx % N === K.
 * For expectedReplica=1 exactly one node in the selected set satisfies this.
 * For expectedReplica>1 the first matching node is returned (caller may
 * implement its own replica selection on top).
 *
 * globalSegIdx = startSegmentIndex + localSegmentIndex, where
 * startSegmentIndex = Math.floor(tx.startEntryIndex / DEFAULT_SEGMENT_MAX_CHUNKS).
 */
export function nodeForSegment(
    selected: ShardedNode[],
    globalSegIdx: number
): ShardedNode | undefined {
    return selected.find(
        (n) => globalSegIdx % n.config.numShard === n.config.shardId
    )
}

export function checkReplica(
    shardConfigs: ShardConfig[],
    expectedReplica: number
): boolean {
    const shardedNodes: ShardedNode[] = shardConfigs.map((c) => ({
        url: '',
        config: { numShard: c.numShard, shardId: c.shardId },
        latency: 0,
        since: 0,
    }))
    const [, ok] = selectNodes(shardedNodes, expectedReplica)
    return ok
}

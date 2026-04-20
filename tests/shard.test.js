// Tests for selectNodes, nodeForSegment, checkReplica
// Imports from the main barrel (validates the export is wired up correctly).
const { selectNodes, nodeForSegment, checkReplica } = require('../lib.commonjs/index.js')

// ─── Helpers ──────────────────────────────────────────────────────────────

function node(url, numShard, shardId) {
    return { url, config: { numShard, shardId }, latency: 0, since: 0 }
}

/**
 * Verify that `selected` is a valid covering set for `expectedReplica`.
 * For each replica r in [0, expectedReplica), every segment index class
 * mod the LCM of all numShards must be covered by exactly one node per
 * replica.  We do a simpler check: for any consecutive numShard * LCM
 * global segment indices, every index is covered by exactly `expectedReplica`
 * selected nodes.
 *
 * Practical shorthand: use the segment tree algorithm itself via checkReplica.
 */
function isCovering(selected, expectedReplica) {
    const shardConfigs = selected.map((n) => n.config)
    return checkReplica(shardConfigs, expectedReplica)
}

// ─── selectNodes – basic ──────────────────────────────────────────────────

test('selectNodes: single full node covers replica=1', () => {
    const nodes = [node('A', 1, 0)]
    const [selected, ok] = selectNodes(nodes, 1)
    expect(ok).toBe(true)
    expect(selected).toHaveLength(1)
    expect(selected[0].url).toBe('A')
})

test('selectNodes: two half-shards together cover replica=1', () => {
    const nodes = [node('A', 2, 0), node('B', 2, 1)]
    const [selected, ok] = selectNodes(nodes, 1)
    expect(ok).toBe(true)
    expect(selected).toHaveLength(2)
    expect(isCovering(selected, 1)).toBe(true)
})

test('selectNodes: insufficient nodes returns false', () => {
    // Only shard 0 of 2 is available — cannot form a full covering set
    const nodes = [node('A', 2, 0)]
    const [selected, ok] = selectNodes(nodes, 1)
    expect(ok).toBe(false)
    expect(selected).toHaveLength(0)
})

test('selectNodes: replica=2 requires two full covering sets', () => {
    const nodes = [
        node('A', 1, 0),
        node('B', 1, 0), // second full node
    ]
    const [selected, ok] = selectNodes(nodes, 2)
    expect(ok).toBe(true)
    expect(selected).toHaveLength(2)
    expect(isCovering(selected, 2)).toBe(true)
})

test('selectNodes: replica=2 with sharded nodes', () => {
    const nodes = [
        node('A', 2, 0), node('B', 2, 1), // set 1
        node('C', 2, 0), node('D', 2, 1), // set 2
    ]
    const [selected, ok] = selectNodes(nodes, 2)
    expect(ok).toBe(true)
    expect(selected).toHaveLength(4)
    expect(isCovering(selected, 2)).toBe(true)
})

test('selectNodes: mixed shard configs', () => {
    // 1/4, 1/2, 0/2 — the segment tree is needed to handle this correctly
    const nodes = [
        node('A', 4, 1),
        node('B', 2, 1),
        node('C', 2, 0),
    ]
    const [selected, ok] = selectNodes(nodes, 1)
    expect(ok).toBe(true)
    expect(isCovering(selected, 1)).toBe(true)
})

// ─── selectNodes – method parameter ──────────────────────────────────────

test("selectNodes 'min': prefers coarser nodes (numShard=1 beats two numShard=2)", () => {
    const nodes = [
        node('Full', 1, 0),
        node('Half0', 2, 0),
        node('Half1', 2, 1),
    ]
    const [selected, ok] = selectNodes(nodes, 1, 'min')
    expect(ok).toBe(true)
    // min sort: Full (numShard=1) comes first and covers everything alone
    expect(selected).toHaveLength(1)
    expect(selected[0].url).toBe('Full')
})

test("selectNodes 'max': prefers finer-grained nodes (numShard=2 picked before numShard=1)", () => {
    const nodes = [
        node('Full', 1, 0),
        node('Half0', 2, 0),
        node('Half1', 2, 1),
    ]
    const [selected, ok] = selectNodes(nodes, 1, 'max')
    expect(ok).toBe(true)
    // max sort: Half0, Half1 (numShard=2) come first, together they cover all
    expect(selected).toHaveLength(2)
    expect(selected.map((n) => n.url).sort()).toEqual(['Half0', 'Half1'])
    expect(isCovering(selected, 1)).toBe(true)
})

test("selectNodes 'random': result is a valid covering set", () => {
    const nodes = [
        node('A', 2, 0),
        node('B', 2, 1),
        node('C', 1, 0),
    ]
    // Run several times to exercise the random path
    for (let i = 0; i < 20; i++) {
        const [selected, ok] = selectNodes(nodes, 1, 'random')
        expect(ok).toBe(true)
        expect(isCovering(selected, 1)).toBe(true)
    }
})

test('selectNodes: does not mutate the input array', () => {
    const nodes = [
        node('B', 2, 1),
        node('A', 2, 0),
        node('C', 1, 0),
    ]
    const original = nodes.map((n) => n.url)
    selectNodes(nodes, 1, 'min')
    selectNodes(nodes, 1, 'max')
    selectNodes(nodes, 1, 'random')
    expect(nodes.map((n) => n.url)).toEqual(original)
})

test('selectNodes: expectedReplica=0 returns false', () => {
    const [selected, ok] = selectNodes([node('A', 1, 0)], 0)
    expect(ok).toBe(false)
    expect(selected).toHaveLength(0)
})

// ─── nodeForSegment ───────────────────────────────────────────────────────

test('nodeForSegment: routes segments by shard', () => {
    const selected = [
        node('Even', 2, 0),
        node('Odd', 2, 1),
    ]
    expect(nodeForSegment(selected, 0)?.url).toBe('Even') // 0 % 2 = 0
    expect(nodeForSegment(selected, 1)?.url).toBe('Odd')  // 1 % 2 = 1
    expect(nodeForSegment(selected, 2)?.url).toBe('Even') // 2 % 2 = 0
    expect(nodeForSegment(selected, 3)?.url).toBe('Odd')  // 3 % 2 = 1
})

test('nodeForSegment: full node (numShard=1) handles every segment', () => {
    const selected = [node('Full', 1, 0)]
    for (let i = 0; i < 10; i++) {
        expect(nodeForSegment(selected, i)?.url).toBe('Full')
    }
})

test('nodeForSegment: four-way sharding', () => {
    const selected = [
        node('N0', 4, 0),
        node('N1', 4, 1),
        node('N2', 4, 2),
        node('N3', 4, 3),
    ]
    for (let i = 0; i < 12; i++) {
        expect(nodeForSegment(selected, i)?.url).toBe(`N${i % 4}`)
    }
})

test('nodeForSegment: returns undefined when no node covers the segment', () => {
    // Only shard 0 of 2 present — odd segments are uncovered
    const selected = [node('Half0', 2, 0)]
    expect(nodeForSegment(selected, 0)?.url).toBe('Half0')
    expect(nodeForSegment(selected, 1)).toBeUndefined()
})

// ─── checkReplica ─────────────────────────────────────────────────────────

test('checkReplica: two half-shards satisfy replica=1', () => {
    expect(checkReplica([{ numShard: 2, shardId: 0 }, { numShard: 2, shardId: 1 }], 1)).toBe(true)
})

test('checkReplica: single half-shard cannot satisfy replica=1', () => {
    expect(checkReplica([{ numShard: 2, shardId: 0 }], 1)).toBe(false)
})

test('checkReplica: four quarter-shards satisfy replica=1', () => {
    const configs = [0, 1, 2, 3].map((id) => ({ numShard: 4, shardId: id }))
    expect(checkReplica(configs, 1)).toBe(true)
})

test('checkReplica: replica=2 needs two full sets', () => {
    // Only one full node — not enough for replica=2
    expect(checkReplica([{ numShard: 1, shardId: 0 }], 2)).toBe(false)
    // Two full nodes — OK
    expect(
        checkReplica(
            [{ numShard: 1, shardId: 0 }, { numShard: 1, shardId: 0 }],
            2
        )
    ).toBe(true)
})

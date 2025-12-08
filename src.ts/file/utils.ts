import { DEFAULT_CHUNK_SIZE } from '../constant.js'

export function numSplits(total: number, unit: number): number {
    return Math.floor((total - 1) / unit) + 1
}

export function nextPow2(input: number): number {
    if (input <= 0) return 1
    if (input <= 1) return 1

    // For large numbers beyond 32-bit range, use Math approach
    if (input > 0x7fffffff) {
        const log = Math.log2(input)
        const ceil = Math.ceil(log)
        return Math.pow(2, ceil)
    }

    // For smaller numbers, use the efficient bitwise approach
    let x = input
    x -= 1
    x |= x >> 16
    x |= x >> 8
    x |= x >> 4
    x |= x >> 2
    x |= x >> 1
    x += 1
    return x
}

export function computePaddedSize(chunks: number): [number, number] {
    let chunksNextPow2 = nextPow2(chunks)
    if (chunksNextPow2 === chunks) {
        return [chunksNextPow2, chunksNextPow2]
    }

    let minChunk
    if (chunksNextPow2 >= 16) {
        minChunk = Math.floor(chunksNextPow2 / 16)
    } else {
        minChunk = 1
    }

    const paddedChunks = numSplits(chunks, minChunk) * minChunk
    return [paddedChunks, chunksNextPow2]
}

export function iteratorPaddedSize(
    dataSize: number,
    flowPadding: boolean
): number {
    const chunks = numSplits(dataSize, DEFAULT_CHUNK_SIZE)
    let paddedSize: number
    if (flowPadding) {
        const [paddedChunks] = computePaddedSize(chunks)
        paddedSize = paddedChunks * DEFAULT_CHUNK_SIZE
    } else {
        paddedSize = chunks * DEFAULT_CHUNK_SIZE
    }
    return paddedSize
}

import { keccak256 } from '@ethersproject/keccak256';
export const DEFAULT_CHUNK_SIZE = 256; // bytes
export const DEFAULT_SEGMENT_MAX_CHUNKS = 1024;
export const DEFAULT_SEGMENT_SIZE = DEFAULT_CHUNK_SIZE * DEFAULT_SEGMENT_MAX_CHUNKS;
export const EMPTY_CHUNK = new Uint8Array(DEFAULT_CHUNK_SIZE);
export const EMPTY_CHUNK_HASH = keccak256(EMPTY_CHUNK);
export const SMALL_FILE_SIZE_THRESHOLD = 256 * 1024;
export const TIMEOUT_MS = 3000_000; // 60 seconds
export const DEFAULT_BATCH_SIZE = 10;
export const ZERO_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000';
//# sourceMappingURL=constant.js.map
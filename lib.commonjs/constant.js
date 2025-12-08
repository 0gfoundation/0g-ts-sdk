"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZERO_HASH = exports.DEFAULT_BATCH_SIZE = exports.TIMEOUT_MS = exports.SMALL_FILE_SIZE_THRESHOLD = exports.EMPTY_CHUNK_HASH = exports.EMPTY_CHUNK = exports.DEFAULT_SEGMENT_SIZE = exports.DEFAULT_SEGMENT_MAX_CHUNKS = exports.DEFAULT_CHUNK_SIZE = void 0;
const keccak256_1 = require("@ethersproject/keccak256");
exports.DEFAULT_CHUNK_SIZE = 256; // bytes
exports.DEFAULT_SEGMENT_MAX_CHUNKS = 1024;
exports.DEFAULT_SEGMENT_SIZE = exports.DEFAULT_CHUNK_SIZE * exports.DEFAULT_SEGMENT_MAX_CHUNKS;
exports.EMPTY_CHUNK = new Uint8Array(exports.DEFAULT_CHUNK_SIZE);
exports.EMPTY_CHUNK_HASH = (0, keccak256_1.keccak256)(exports.EMPTY_CHUNK);
exports.SMALL_FILE_SIZE_THRESHOLD = 256 * 1024;
exports.TIMEOUT_MS = 3000_000; // 60 seconds
exports.DEFAULT_BATCH_SIZE = 10;
exports.ZERO_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000';
//# sourceMappingURL=constant.js.map
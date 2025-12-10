"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultUploadOption = void 0;
exports.mergeUploadOptions = mergeUploadOptions;
exports.defaultUploadOption = {
    tags: '0x',
    finalityRequired: true,
    taskSize: 1,
    expectedReplica: 1,
    fragmentSize: 1024 * 1024 * 1024 * 4, // 4GB
    skipTx: false,
    fee: BigInt(0),
};
/**
 * Merges user-provided upload options with default values
 */
function mergeUploadOptions(userOptions = {}) {
    return {
        tags: userOptions.tags ?? exports.defaultUploadOption.tags,
        finalityRequired: userOptions.finalityRequired ??
            exports.defaultUploadOption.finalityRequired,
        taskSize: userOptions.taskSize ?? exports.defaultUploadOption.taskSize,
        expectedReplica: userOptions.expectedReplica ?? exports.defaultUploadOption.expectedReplica,
        fragmentSize: userOptions.fragmentSize ?? exports.defaultUploadOption.fragmentSize,
        skipTx: userOptions.skipTx ?? exports.defaultUploadOption.skipTx,
        fee: userOptions.fee ?? exports.defaultUploadOption.fee,
        nonce: userOptions.nonce,
    };
}
//# sourceMappingURL=types.js.map
export const defaultUploadOption = {
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
export function mergeUploadOptions(userOptions = {}) {
    return {
        tags: userOptions.tags ?? defaultUploadOption.tags,
        finalityRequired: userOptions.finalityRequired ??
            defaultUploadOption.finalityRequired,
        taskSize: userOptions.taskSize ?? defaultUploadOption.taskSize,
        expectedReplica: userOptions.expectedReplica ?? defaultUploadOption.expectedReplica,
        fragmentSize: userOptions.fragmentSize ?? defaultUploadOption.fragmentSize,
        skipTx: userOptions.skipTx ?? defaultUploadOption.skipTx,
        fee: userOptions.fee ?? defaultUploadOption.fee,
        nonce: userOptions.nonce,
    };
}
//# sourceMappingURL=types.js.map
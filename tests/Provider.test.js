const { StorageNode } = require("../lib.commonjs/index.js");

// Live-node smoke test. Skipped by default because it hits a hardcoded
// testnet IP that isn't guaranteed to be up during CI. Re-enable locally
// by changing `test.skip` to `test` and pointing the URL at a reachable node.
test.skip("Provider", async () => {
    const provider = new StorageNode('http://47.92.4.77:5678');

    const status = await provider.getStatus();
    console.log(status);
});
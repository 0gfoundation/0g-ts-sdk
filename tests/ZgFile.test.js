const { exec } = require("child_process");
const { ZgFile } = require("../lib.commonjs/index.js");
const { join } = require("path");

test("ZegogStorageFile", async () => {
    const file = await ZgFile.fromFilePath(join(__dirname, "./example.ts"));
    const [tree, err] = await file.merkleTree();
    expect(err).toBe(null);
    expect(tree?.rootHash()).toBe("0x76f3f9a729197e04a7b46c3fe0af7e56d8f0f39dacc3a36496fc9242a9beaa23");
    await file.close();

    const file2 = await ZgFile.fromFilePath(join(__dirname, "./example.md"));
    const [tree2, err2] = await file2.merkleTree();
    expect(err2).toBe(null);
    expect(tree2?.rootHash()).toBe("0x95034699d3a494d05642ba74ab7f07fc318070df588c8adc42a81168880cad9a"); 
    await file2.close();
});

test("createSubmission", async () => {
    const file = await ZgFile.fromFilePath(join(__dirname, "./example.md"));
    const [submission, err] = await file.createSubmission("test");
    expect(err).toBe(null);
    expect(submission.data.length).toBe(20182);
    expect(submission.data.nodes.length).toBe(2);
    expect(submission.data.nodes[0].height).toBe(6);
    expect(submission.data.nodes[1].height).toBe(4);
    expect(submission.data.nodes[0].root).toBe('0x67ffe8254bf275aebaaa4aea83e2304b75f0021cecdfeb5555b9af0d6d4db132');
    expect(submission.data.nodes[1].root).toBe('0x573f918e76aa3b778c0774b870c8ba3a7d16ba2900c904af68fb9af224d4511f');
    await file.close();
});

const { MerkleTree, LeafNode } = require('../lib.commonjs/file/MerkleTree.js');

test("Node.fromLeftAndRight", () => {
    const left = LeafNode.fromContent(createChunkData(0));
    const right = LeafNode.fromContent(createChunkData(1));
    const node = LeafNode.fromLeftAndRight(left, right);
    expect(node.hash).toBe("0xe733f492cef3dbbf28ba4584ca5a35d3e87604a6ad16ff9f10970af2c467b056");
    expect(left.isLeftSide()).toBe(true);
    expect(right.isLeftSide()).toBe(false);
    expect(node.isLeftSide()).toBe(false);
});

test('One-Node Tree Root', () => {
    const content0 = createChunkData(0);
    const node = LeafNode.fromContent(content0);
    const tree = createTreeByChunks(1);
    expect(tree.root?.hash).toBe(node.hash);
    expect(tree.leaves.length).toBe(1);
});

test('Two-Node Tree Root', () => {
    const node0 = LeafNode.fromContent(createChunkData(0));
    const node1 = LeafNode.fromContent(createChunkData(1));
    const tree = createTreeByChunks(2);
    expect(tree.leaves.length).toBe(2);
    expect(tree.leaves[0].hash).toBe(node0.hash);
    expect(tree.leaves[1].hash).toBe(node1.hash);
    const parent = LeafNode.fromLeftAndRight(node0, node1);
    expect(tree.root?.hash).toBe(parent.hash);
});

test('Multiple-Node Tree Root', () => {
    expect(createTreeByChunks(3).root?.hash).toBe("0x6f5d8d4ca0790ea245a280ece40fb7493d5f957b8d42931e3326ba3fd0c86e41");
    expect(createTreeByChunks(4).root?.hash).toBe("0x2418ddec22d6fb98525835c9876a95db78491cc3430df47a9ed4b2a337c5452c");
    expect(createTreeByChunks(5).root?.hash).toBe("0x2dea03c693750777940bcd0cc3f5d93543c075fa3b9a07b9fd86ec8fbaf6a8b2");
    expect(createTreeByChunks(6).root?.hash).toBe("0x318c92000aefba6ebf570a8a6daa57aa643f04350ffbe583999ddd9e24ceb147");
    expect(createTreeByChunks(7).root?.hash).toBe("0xca80116fb7fb8d6ef4a47e322f22e94ae8beb03e6fcbf8ab59c4d6f54fe42c4d");
    expect(createTreeByChunks(35).root?.hash).toBe("0x209c511bf4349096c4951cb825bebbf219de745c2b36261bed8c64a105982912");
    expect(createTreeByChunks(36).root?.hash).toBe("0xc8855b6bfb57c37673397678dd3199fbbe6cd3b0b4cda2800cfab298d271ae2a");
});

test('Proof', () => {
    for(let num = 1; num <= 32; num++) {
        const tree = createTreeByChunks(num);

        for (let i = 0; i < num; i++) {
            const proof = tree.proofAt(i);
            const validate = proof.validate(tree.rootHash(), createChunkData(i), i, num);
            expect(validate).toBe(null);
        }
    } 
});

test("RootBySegments", () => {
    for (let chunks = 1; chunks <= 256; chunks ++) {
        const root1 = createTreeByChunks(chunks).rootHash();
        const root2 = calculateRootBySegments(chunks, 4);
        const root3 = calculateRootBySegments(chunks, 16);

        expect(root1).toBe(root2);
        expect(root2).toBe(root3);
    }
});

function createChunkData(i) {
    return Buffer.from(`chunk data - ${i}`, 'utf8');
}

function createTreeByChunks(chunks) {
    const builder = new MerkleTree();

    for(let i = 0; i < chunks; i++) {
        builder.addLeaf(createChunkData(i));
    }
    
    return builder.build();
}

function calculateRootBySegments(chunks, chunksPerSegment) {
    const builder = new MerkleTree();

    for (let i = 0; i < chunks; i += chunksPerSegment) {
        const segBuilder = new MerkleTree();

        for (let j = 0; j < chunksPerSegment; j++) {
            const index = i + j;
            if (index >= chunks) {
                break;
            }
            segBuilder.addLeaf(createChunkData(index));
        }

        builder.addLeafByHash(segBuilder.build()?.rootHash());
    }

    return builder.build()?.rootHash();
}
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import nodePolyfills from 'rollup-plugin-polyfill-node';

/**
 * @type {import('rollup').RollupOptions}
 */
const nodeBuiltins = ['fs', 'path', 'fs/promises', 'node:fs/promises', 'node:fs', 'node:path']

export default [
    {
        input: 'lib.esm/index.js',
        external: nodeBuiltins,
        output: {
            file: 'dist/zgstorage.esm.js',
            format: 'esm'
        },
        treeshake: true,
        plugins: [nodeResolve({
            mainFields: [ "browser", "module", "main" ],
            browser: true
        }), commonjs()],
    },
    {
        input: 'lib.esm/index.js',
        external: nodeBuiltins,
        output: {
            file: 'dist/zgstorage.umd.js',
            format: 'umd',
            name: 'zgstorage',
            inlineDynamicImports: true,
        },
        treeshake: true,
        plugins: [
            nodeResolve({
                mainFields: [ "browser", "module", "main" ],
                browser: true
            }),
            commonjs(),
            nodePolyfills({
                include: ['events']
            })
        ],
    }
];
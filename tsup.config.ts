import { defineConfig } from 'tsup';

// The core barrel (`.`) stays runtime-agnostic; the Node-specific engine, ambient-session, and KMS
// adapters ship as separate entry points so a universal consumer never pulls `node:*` into its bundle.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'node/index': 'src/node/index.ts',
    'crypto/noble': 'src/crypto/noble.ts',
    'l2/adapters/aws-kms': 'src/l2/adapters/aws-kms.ts',
  },
  format: ['esm'],
  target: 'es2023',
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
});

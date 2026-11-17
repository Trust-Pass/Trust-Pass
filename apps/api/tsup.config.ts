import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { server: 'src/server.ts', seed: 'src/scripts/seed.ts', 'rewrap-keys': 'src/scripts/rewrap-keys.ts', keys: 'src/scripts/keys.ts', backup: 'src/scripts/backup.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // Bundle the workspace package; keep real npm dependencies external.
  noExternal: ['@trustpass/shared'],
});

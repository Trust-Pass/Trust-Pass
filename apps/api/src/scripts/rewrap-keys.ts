/**
 * Kept for compatibility: same as `pnpm keys:rewrap` (see src/scripts/keys.ts).
 * Moves every data key and link token to the current keys; --dry-run writes nothing.
 */
import { runKeysCli } from './keys';

runKeysCli(['rewrap', ...process.argv.slice(2)])
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });

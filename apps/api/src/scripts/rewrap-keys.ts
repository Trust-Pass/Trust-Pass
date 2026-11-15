/**
 * Master-key rotation. After setting a new MASTER_KEY + MASTER_KEY_VERSION and
 * moving the old key into PREVIOUS_MASTER_KEYS, run:
 *
 *   pnpm keys:rewrap
 *
 * Every document's data key is unwrapped with its old master key and wrapped
 * again with the current one. File ciphertext is not touched.
 */
import { PrismaClient } from '@prisma/client';
import { loadConfig } from '../config';
import { unwrapDataKey, wrapDataKey } from '../lib/crypto';

async function main() {
  const config = loadConfig();
  const prisma = new PrismaClient();
  const current = config.masterKeys.current.version;
  const keys = await prisma.documentKey.findMany({ where: { kekVersion: { not: current } } });
  let done = 0;
  for (const key of keys) {
    const dek = unwrapDataKey(config, key, key.documentId);
    const wrapped = wrapDataKey(config, dek, key.documentId);
    dek.fill(0);
    await prisma.documentKey.update({ where: { documentId: key.documentId }, data: wrapped });
    done++;
  }
  console.log(`Re-wrapped ${done} data key(s) with master key version ${current}`);
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});

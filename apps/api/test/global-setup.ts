import { execSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { PrismaClient } from '@prisma/client';
import { TEST_DATABASE_URL, TEST_KMS_KEY_FILE } from './env';

export default async function setup() {
  // Apply the real migrations (including triggers) to the test database.
  execSync('npx prisma migrate deploy', {
    stdio: 'pipe',
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
  });
  // Each run gets a new random fake-KMS root key, so keys and data left by an earlier
  // run (encrypted under the old root key) are removed first.
  const prisma = new PrismaClient({ datasources: { db: { url: TEST_DATABASE_URL } } });
  try {
    await prisma.$transaction([
      prisma.$executeRawUnsafe(`SELECT set_config('trustpass.allow_key_destroy', 'on', true)`),
      prisma.$executeRawUnsafe(`TRUNCATE "key_encryption_keys", "document_keys"`),
    ]);
  } finally {
    await prisma.$disconnect();
  }
  rmSync(TEST_KMS_KEY_FILE, { force: true });
}

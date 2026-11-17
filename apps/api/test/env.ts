import { tmpdir } from 'node:os';
import path from 'node:path';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgresql://trustpass:trustpass_dev@localhost:5432/trustpass_test';

/**
 * Fake KMS root key shared by every test file in one run (files run in separate
 * processes). global-setup deletes it, so each run starts with a new random key.
 */
export const TEST_KMS_KEY_FILE = path.join(tmpdir(), 'trustpass-test-kms', 'root.key');

import { randomBytes } from 'node:crypto';
import { existsSync, linkSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { decrypt, encrypt } from '../crypto';
import { KmsError, type KmsProvider } from './types';

/**
 * Stand-in for a real KMS, for development and tests only (refused in production).
 *
 * There is no built-in key: the root key is either random for this process, or random
 * and stored in a local file the first time it is needed (FAKE_KMS_KEY_FILE), so a
 * developer's data survives restarts. Ciphertext format: "FKMS1" | iv | tag | ciphertext.
 */
const MAGIC = Buffer.from('FKMS1', 'ascii');
const HEADER = MAGIC.length;

let processKey: Buffer | null = null;

/** Reads the fake root key, creating it atomically with mode 0600 if the file does not exist. */
export function loadOrCreateFakeKmsKey(file: string): Buffer {
  const full = path.resolve(file);
  if (!existsSync(full)) {
    mkdirSync(path.dirname(full), { recursive: true, mode: 0o700 });
    const tmp = `${full}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    writeFileSync(tmp, randomBytes(32).toString('base64'), { mode: 0o600 });
    try {
      // link() fails if the file already exists, so two processes can never write different keys.
      linkSync(tmp, full);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    } finally {
      unlinkSync(tmp);
    }
  }
  const key = Buffer.from(readFileSync(full, 'utf8').trim(), 'base64');
  if (key.length !== 32) throw new KmsError('The fake KMS key file does not hold a 32-byte key');
  return key;
}

export class FakeKms implements KmsProvider {
  readonly name = 'fake-kms' as const;
  readonly keyName: string;
  private readonly key: Buffer;

  constructor(options: { key?: Buffer; keyFile?: string } = {}) {
    if (options.key) {
      if (options.key.length !== 32) throw new KmsError('Fake KMS key must be 32 bytes');
      this.key = Buffer.from(options.key);
      this.keyName = 'fake-kms/in-memory';
    } else if (options.keyFile) {
      this.key = loadOrCreateFakeKmsKey(options.keyFile);
      this.keyName = `fake-kms/file/${path.basename(options.keyFile)}`;
    } else {
      processKey ??= randomBytes(32);
      this.key = processKey;
      this.keyName = 'fake-kms/process';
    }
  }

  async encrypt(plaintext: Buffer, aad: string): Promise<Buffer> {
    const sealed = encrypt(this.key, plaintext, `fake-kms|${aad}`);
    return Buffer.concat([MAGIC, sealed.iv, sealed.tag, sealed.ciphertext]);
  }

  async decrypt(ciphertext: Buffer, aad: string): Promise<Buffer> {
    if (ciphertext.length < HEADER + 28 || !ciphertext.subarray(0, HEADER).equals(MAGIC)) {
      throw new KmsError('Not a fake KMS ciphertext');
    }
    try {
      return decrypt(
        this.key,
        {
          iv: ciphertext.subarray(HEADER, HEADER + 12),
          tag: ciphertext.subarray(HEADER + 12, HEADER + 28),
          ciphertext: ciphertext.subarray(HEADER + 28),
        },
        `fake-kms|${aad}`,
      );
    } catch {
      throw new KmsError('KMS could not decrypt the key: wrong root key or wrong context');
    }
  }
}

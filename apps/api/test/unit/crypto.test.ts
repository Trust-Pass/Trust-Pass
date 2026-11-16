import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config';
import {
  decrypt,
  encrypt,
  fileAad,
  generateDataKey,
  hashToken,
  open,
  randomToken,
  seal,
  unwrapDataKey,
  wrapDataKey,
} from '../../src/lib/crypto';
import { testConfig, TEST_SECRETS } from '../helpers';

describe('AES-256-GCM', () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from('university certificate contents');

  it('round-trips and never returns the plaintext as ciphertext', () => {
    const sealed = encrypt(key, plaintext, 'doc-1');
    expect(sealed.iv).toHaveLength(12);
    expect(sealed.tag).toHaveLength(16);
    expect(sealed.ciphertext.equals(plaintext)).toBe(false);
    expect(decrypt(key, sealed, 'doc-1').equals(plaintext)).toBe(true);
  });

  it('uses a fresh IV every time', () => {
    const a = encrypt(key, plaintext, 'x');
    const b = encrypt(key, plaintext, 'x');
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it('rejects a modified ciphertext (integrity)', () => {
    const sealed = encrypt(key, plaintext, 'doc-1');
    sealed.ciphertext[0]! ^= 0xff;
    expect(() => decrypt(key, sealed, 'doc-1')).toThrow();
  });

  it('rejects a modified authentication tag', () => {
    const sealed = encrypt(key, plaintext, 'doc-1');
    sealed.tag[3]! ^= 0x01;
    expect(() => decrypt(key, sealed, 'doc-1')).toThrow();
  });

  it('rejects ciphertext moved to another record (AAD binding)', () => {
    const sealed = encrypt(key, plaintext, fileAad('doc-1', 'owner-1'));
    expect(() => decrypt(key, sealed, fileAad('doc-2', 'owner-1'))).toThrow();
    expect(() => decrypt(key, sealed, fileAad('doc-1', 'owner-2'))).toThrow();
  });

  it('rejects the wrong key', () => {
    const sealed = encrypt(key, plaintext, 'a');
    expect(() => decrypt(randomBytes(32), sealed, 'a')).toThrow();
  });

  it('seal/open packs iv, tag and ciphertext together', () => {
    const blob = seal(key, 'Active', 'claim');
    expect(open(key, blob, 'claim').toString()).toBe('Active');
    expect(() => open(key, blob, 'other')).toThrow();
  });
});

describe('envelope encryption', () => {
  it('wraps a data key with the master key and unwraps it', () => {
    const config = testConfig();
    const dek = generateDataKey();
    const wrapped = wrapDataKey(config, dek, 'doc-9');
    expect(Buffer.from(wrapped.wrappedDek).equals(dek)).toBe(false);
    expect(wrapped.kekVersion).toBe(1);
    expect(unwrapDataKey(config, wrapped, 'doc-9').equals(dek)).toBe(true);
    expect(() => unwrapDataKey(config, wrapped, 'doc-10')).toThrow();
  });

  it('supports master-key rotation through PREVIOUS_MASTER_KEYS', () => {
    const v1 = testConfig();
    const dek = generateDataKey();
    const wrappedV1 = wrapDataKey(v1, dek, 'doc-r');

    const v2 = testConfig({
      MASTER_KEY: 'second-master-key-0123456789-abcdefghijklmnopqrstu',
      MASTER_KEY_VERSION: '2',
      PREVIOUS_MASTER_KEYS: `1:${TEST_SECRETS.MASTER_KEY}`,
    });
    expect(unwrapDataKey(v2, wrappedV1, 'doc-r').equals(dek)).toBe(true);
    const wrappedV2 = wrapDataKey(v2, dek, 'doc-r');
    expect(wrappedV2.kekVersion).toBe(2);

    // Without the old key configured, version 1 keys cannot be opened.
    const v2only = testConfig({ MASTER_KEY: 'second-master-key-0123456789-abcdefghijklmnopqrstu', MASTER_KEY_VERSION: '2' });
    expect(() => unwrapDataKey(v2only, wrappedV1, 'doc-r')).toThrow(/version 1/);
  });

  it('derives different keys for different purposes from configured secrets', () => {
    const config = testConfig();
    expect(config.masterKeys.current.key.equals(config.ipHashKey)).toBe(false);
    expect(config.masterKeys.current.key.toString('utf8')).not.toContain(TEST_SECRETS.MASTER_KEY);
  });
});

describe('tokens', () => {
  it('are 256-bit, URL-safe and stored only as SHA-256 hashes', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hashToken(token)).toMatch(/^[a-f0-9]{64}$/);
    expect(hashToken(token)).not.toContain(token);
  });
});

describe('configuration safety', () => {
  const base = { NODE_ENV: 'production', DATABASE_URL: 'postgres://x', APP_URL: 'https://trustpass.example', ...TEST_SECRETS };

  it('refuses the simulated geo provider in production', () => {
    expect(() => loadConfig({ ...base, GEO_PROVIDER: 'simulated' })).toThrow(/refused in production/);
  });

  it('refuses plain http and trust-all proxies in production', () => {
    expect(() => loadConfig({ ...base, APP_URL: 'http://trustpass.example' })).toThrow(/https/);
    expect(() => loadConfig({ ...base, TRUST_PROXY: 'true' })).toThrow(/unsafe/);
  });

  it('refuses short secrets', () => {
    expect(() => loadConfig({ ...base, MASTER_KEY: 'short' })).toThrow(/MASTER_KEY/);
  });

  it('uses a __Host- secure cookie in production', () => {
    const config = loadConfig(base);
    expect(config.cookieName).toBe('__Host-tp_session');
    expect(config.cookieSecure).toBe(true);
  });
});

describe('trusted proxy configuration', () => {
  const base = { NODE_ENV: 'production', DATABASE_URL: 'postgres://x', APP_URL: 'https://trustpass.example', ...TEST_SECRETS };

  it('accepts hop counts and private-range lists', () => {
    expect(loadConfig({ ...base, TRUST_PROXY: '2' }).trustProxy).toBe(2);
    expect(loadConfig({ ...base, TRUST_PROXY: 'loopback, linklocal,uniquelocal,100.64.0.0/10' }).trustProxy).toEqual([
      'loopback',
      'linklocal',
      'uniquelocal',
      '100.64.0.0/10',
    ]);
  });

  it('rejects anything else', () => {
    expect(() => loadConfig({ ...base, TRUST_PROXY: 'everyone' })).toThrow(/not loopback/);
    expect(() => loadConfig({ ...base, TRUST_PROXY: '10.0.0.0/99' })).toThrow(/not loopback/);
  });
});

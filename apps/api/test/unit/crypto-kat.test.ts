import { createCipheriv } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decrypt, open } from '../../src/lib/crypto';

/**
 * E1: known-answer tests. The round-trip tests in crypto.test.ts prove the wrapper is
 * self-consistent; these prove it is real AES-256-GCM by matching published vectors
 * (McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 15 and 16,
 * also used by NIST CAVP).
 */
const KEY = Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex');
const IV = Buffer.from('cafebabefacedbaddecaf888', 'hex');
const PLAINTEXT = Buffer.from(
  'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
  'hex',
);
const CIPHERTEXT = Buffer.from(
  '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
  'hex',
);
const TAG_TC15 = Buffer.from('b094dac5d93471bdec1a502270e3cc6c', 'hex');

describe('AES-256-GCM known-answer tests', () => {
  it('decrypt() reproduces the published plaintext for test case 15', () => {
    const out = decrypt(KEY, { iv: IV, tag: TAG_TC15, ciphertext: CIPHERTEXT }, '');
    expect(out.equals(PLAINTEXT)).toBe(true);
  });

  it('open() reads the iv | tag | ciphertext layout used for sealed fields', () => {
    const packed = Buffer.concat([IV, TAG_TC15, CIPHERTEXT]);
    expect(open(KEY, packed, '').equals(PLAINTEXT)).toBe(true);
  });

  it('rejects the published ciphertext when one tag bit is flipped', () => {
    const tag = Buffer.from(TAG_TC15);
    tag[0]! ^= 0x01;
    expect(() => decrypt(KEY, { iv: IV, tag, ciphertext: CIPHERTEXT }, '')).toThrow();
  });

  it('the platform cipher matches test case 16 (with additional authenticated data)', () => {
    const cipher = createCipheriv('aes-256-gcm', KEY, IV);
    cipher.setAAD(Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddad2', 'hex'));
    const ct = Buffer.concat([cipher.update(PLAINTEXT.subarray(0, 60)), cipher.final()]);
    expect(ct.equals(CIPHERTEXT.subarray(0, 60))).toBe(true);
    expect(cipher.getAuthTag().toString('hex')).toBe('76fc6ece0f4e1768cddf8853bb2d551b');
  });
});

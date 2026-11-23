import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createPresentation,
  ed25519FromSeed,
  issueSdJwt,
  jwkThumbprint,
  publicKeyToJwk,
  verifySdJwt,
  type IssuerRecordForVerify,
} from '../../src/lib/sd-jwt';

const seed = randomBytes(32);
const { privateKey, publicKey } = ed25519FromSeed(seed);
const jwk = publicKeyToJwk(publicKey);
const kid = jwkThumbprint(jwk);
const issuer: IssuerRecordForVerify = {
  id: 'issuer-1',
  name: 'Demo University',
  identifier: 'test:issuer',
  status: 'trusted',
  isSimulated: true,
  publicKeyJwk: jwk,
};
const resolve = async (k: string) => (k === kid ? issuer : null);
const now = new Date('2026-11-15T10:00:00Z');

function issue(overrides: Partial<Parameters<typeof issueSdJwt>[0]> = {}) {
  return issueSdJwt({
    privateKey,
    kid,
    issuer: 'test:issuer',
    vct: 'Test',
    credentialId: '11111111-1111-4111-8111-111111111111',
    documentHash: 'a'.repeat(64),
    issuedAt: new Date('2026-11-01T00:00:00Z'),
    expiresAt: new Date('2027-11-01T00:00:00Z'),
    claims: [
      { name: 'full_name', value: 'Reham Alkhamees' },
      { name: 'student_id', value: '412345678' },
      { name: 'enrollment_status', value: 'Active' },
    ],
    ...overrides,
  });
}

describe('SD-JWT selective disclosure', () => {
  it('signs only digests: no claim value appears in the signed JWT', () => {
    const credential = issue();
    const jwt = credential.sdJwt.split('~')[0]!;
    const payload = Buffer.from(jwt.split('.')[1]!, 'base64url').toString();
    expect(payload).not.toContain('Reham');
    expect(payload).not.toContain('412345678');
    expect(credential.payload._sd).toHaveLength(3);
  });

  it('verifies a presentation that discloses one claim and hides the rest', async () => {
    const credential = issue();
    const status = credential.disclosures.find((d) => d.name === 'enrollment_status')!;
    const presentation = createPresentation(credential.sdJwt, [status.disclosure]);
    expect(presentation).not.toContain(credential.disclosures[0]!.disclosure);

    const result = await verifySdJwt(presentation, resolve, { now });
    expect(result.result).toBe('verified');
    expect(result.disclosed).toEqual([{ name: 'enrollment_status', value: 'Active' }]);
  });

  it('marks a forged claim value as invalid', async () => {
    const credential = issue();
    const forged = Buffer.from(JSON.stringify(['c2FsdA', 'enrollment_status', 'Graduated'])).toString('base64url');
    const result = await verifySdJwt(createPresentation(credential.sdJwt, [forged]), resolve, { now });
    expect(result.result).toBe('invalid');
    expect(result.reason).toMatch(/modified/);
  });

  it('marks a modified payload as invalid (signature check)', async () => {
    const credential = issue();
    const [h, p, s] = credential.sdJwt.split('~')[0]!.split('.');
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString());
    payload.exp += 10 * 365 * 24 * 3600;
    const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}~`;
    const result = await verifySdJwt(tampered, resolve, { now });
    expect(result.result).toBe('invalid');
    expect(result.checks.find((c) => c.name === 'Digital signature')?.passed).toBe(false);
  });

  it('reports an unknown signing key as unverified, not verified', async () => {
    const other = ed25519FromSeed(randomBytes(32));
    const otherJwk = publicKeyToJwk(other.publicKey);
    const credential = issue({ privateKey: other.privateKey, kid: jwkThumbprint(otherJwk) });
    const result = await verifySdJwt(credential.sdJwt, resolve, { now });
    expect(result.result).toBe('unverified');
  });

  it('rejects a signature from another key presented under the trusted key id', async () => {
    const other = ed25519FromSeed(randomBytes(32));
    const credential = issue({ privateKey: other.privateKey });
    const result = await verifySdJwt(credential.sdJwt, resolve, { now });
    expect(result.result).toBe('invalid');
  });

  it('cannot verify credentials of a revoked issuer (its key is no longer trusted)', async () => {
    const credential = issue();
    const result = await verifySdJwt(credential.sdJwt, async () => ({ ...issuer, status: 'revoked' }), { now });
    expect(result.result).toBe('unverified');
    expect(result.reason).toMatch(/revoked/);
    // A changed credential of a revoked issuer is still invalid: the signature is checked first.
    const [h, p, sig] = credential.sdJwt.split('~')[0]!.split('.');
    const forged = `${h}.${p}.${Buffer.from('x'.repeat(64)).toString('base64url')}~`;
    expect((await verifySdJwt(forged, async () => ({ ...issuer, status: 'revoked' }), { now })).result).toBe('invalid');
    expect(sig).toBeTruthy();
  });

  it('never verifies by issuer name: a credential naming the trusted issuer but signed by an unregistered key', async () => {
    const attacker = ed25519FromSeed(randomBytes(32));
    const attackerKid = jwkThumbprint(publicKeyToJwk(attacker.publicKey));
    // Same issuer identifier and claims as the real issuer, attacker's own key.
    const credential = issue({ privateKey: attacker.privateKey, kid: attackerKid });
    const result = await verifySdJwt(credential.sdJwt, resolve, { now });
    expect(result.result).toBe('unverified');
    expect(result.checks.find((c) => c.name === 'Digital signature')).toBeUndefined();
  });

  it('marks a valid signature over a credential that claims another issuer as invalid', async () => {
    const credential = issue({ issuer: 'test:someone-else' });
    const result = await verifySdJwt(credential.sdJwt, resolve, { now });
    expect(result.checks.find((c) => c.name === 'Digital signature')?.passed).toBe(true);
    expect(result.result).toBe('invalid');
  });

  it('cannot verify an unsupported signature algorithm', async () => {
    const credential = issue();
    const [, p, s] = credential.sdJwt.split('~')[0]!.split('.');
    const header = Buffer.from(JSON.stringify({ alg: 'none', kid })).toString('base64url');
    expect((await verifySdJwt(`${header}.${p}.${s}~`, resolve, { now })).result).toBe('unverified');
  });

  it('treats an expired credential as invalid', async () => {
    const credential = issue();
    const result = await verifySdJwt(credential.sdJwt, resolve, { now: new Date('2028-01-01T00:00:00Z') });
    expect(result.result).toBe('invalid');
    expect(result.reason).toMatch(/expired/);
  });

  it('checks the document hash when a file is presented', async () => {
    const credential = issue();
    expect((await verifySdJwt(credential.sdJwt, resolve, { now, fileHash: 'a'.repeat(64) })).result).toBe('verified');
    const bad = await verifySdJwt(credential.sdJwt, resolve, { now, fileHash: 'b'.repeat(64) });
    expect(bad.result).toBe('invalid');
    expect(bad.reason).toMatch(/modified/);
  });

  it('cannot verify input without a supported signature (never "verified")', async () => {
    expect((await verifySdJwt('not-a-credential', resolve, { now })).result).toBe('unverified');
    expect((await verifySdJwt('a.b.c', resolve, { now })).result).toBe('unverified');
    expect((await verifySdJwt('a.b.c~', resolve, { now })).result).toBe('unverified');
  });

  it('rejects duplicated disclosures', async () => {
    const credential = issue();
    const d = credential.disclosures[0]!.disclosure;
    const result = await verifySdJwt(createPresentation(credential.sdJwt, [d, d]), resolve, { now });
    expect(result.result).toBe('invalid');
  });
});

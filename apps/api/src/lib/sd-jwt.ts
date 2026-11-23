import { createPrivateKey, createPublicKey, randomBytes, sign, verify, type JsonWebKey, type KeyObject } from 'node:crypto';
import { sha256Base64Url } from './crypto';

/**
 * Minimal SD-JWT (IETF Selective Disclosure for JWTs) implementation with
 * Ed25519 signatures.
 *
 * Issuance: each selectively disclosable claim becomes a disclosure
 *   base64url(JSON.stringify([salt, name, value])). The issuer signs only the
 *   SHA-256 digests of the disclosures (the `_sd` array).
 * Presentation: the signed JWT plus only the disclosures the holder chooses:
 *   <jwt>~<disclosure>~<disclosure>~
 * Verification: check the signature, then check that every presented
 *   disclosure's digest appears in the signed `_sd` array.
 */

export type ClaimValue = string | number | boolean;

export interface IssuedCredential {
  sdJwt: string;
  disclosures: Array<{ name: string; value: ClaimValue; disclosure: string }>;
  payload: SdJwtPayload;
}

export interface SdJwtPayload {
  iss: string;
  iat: number;
  exp: number;
  vct: string;
  credential_id: string;
  document_hash: string;
  _sd_alg: 'sha-256';
  _sd: string[];
  [key: string]: unknown;
}

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Build an Ed25519 key pair from a 32-byte seed (the private key). */
export function ed25519FromSeed(seed: Buffer): { privateKey: KeyObject; publicKey: KeyObject } {
  if (seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const privateKey = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

export function publicKeyToJwk(publicKey: KeyObject): JsonWebKey {
  const jwk = publicKey.export({ format: 'jwk' });
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
}

export function publicKeyFromJwk(jwk: JsonWebKey): KeyObject {
  return createPublicKey({ key: jwk, format: 'jwk' });
}

/** RFC 7638 thumbprint, used as the key id. */
export function jwkThumbprint(jwk: JsonWebKey): string {
  return sha256Base64Url(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }));
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

export function createDisclosure(name: string, value: ClaimValue): string {
  return b64([randomBytes(16).toString('base64url'), name, value]);
}

export function disclosureDigest(disclosure: string): string {
  return sha256Base64Url(Buffer.from(disclosure, 'ascii'));
}

export function issueSdJwt(options: {
  privateKey: KeyObject;
  kid: string;
  issuer: string;
  vct: string;
  credentialId: string;
  documentHash: string;
  issuedAt: Date;
  expiresAt: Date;
  claims: Array<{ name: string; value: ClaimValue }>;
}): IssuedCredential {
  const disclosures = options.claims.map((c) => ({ ...c, disclosure: createDisclosure(c.name, c.value) }));
  const payload: SdJwtPayload = {
    iss: options.issuer,
    iat: Math.floor(options.issuedAt.getTime() / 1000),
    exp: Math.floor(options.expiresAt.getTime() / 1000),
    vct: options.vct,
    credential_id: options.credentialId,
    document_hash: options.documentHash,
    _sd_alg: 'sha-256',
    // Sorted so the order of digests reveals nothing about the claims.
    _sd: disclosures.map((d) => disclosureDigest(d.disclosure)).sort(),
  };
  const header = { alg: 'EdDSA', typ: 'dc+sd-jwt', kid: options.kid };
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature = sign(null, Buffer.from(signingInput, 'ascii'), options.privateKey).toString('base64url');
  const jwt = `${signingInput}.${signature}`;
  return { sdJwt: `${jwt}~${disclosures.map((d) => `${d.disclosure}~`).join('')}`, disclosures, payload };
}

/** Keep the signed JWT and only the chosen disclosures. */
export function createPresentation(sdJwt: string, keepDisclosures: string[]): string {
  const jwt = sdJwt.split('~')[0];
  return `${jwt}~${keepDisclosures.map((d) => `${d}~`).join('')}`;
}

export interface IssuerRecordForVerify {
  id: string;
  name: string;
  identifier: string;
  status: 'trusted' | 'revoked';
  isSimulated: boolean;
  publicKeyJwk: JsonWebKey;
}

export interface VerificationCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface SdJwtVerification {
  result: 'verified' | 'invalid' | 'unverified';
  reason: string;
  checks: VerificationCheck[];
  issuer: IssuerRecordForVerify | null;
  payload: SdJwtPayload | null;
  disclosed: Array<{ name: string; value: ClaimValue }>;
}

function decodeSegment<T>(segment: string): T {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as T;
}

export async function verifySdJwt(
  presentation: string,
  resolveIssuer: (kid: string) => Promise<IssuerRecordForVerify | null>,
  options: { now: Date; fileHash?: string },
): Promise<SdJwtVerification> {
  const checks: VerificationCheck[] = [];
  const fail = (result: 'invalid' | 'unverified', reason: string, issuer: IssuerRecordForVerify | null = null, payload: SdJwtPayload | null = null): SdJwtVerification => ({
    result,
    reason,
    checks,
    issuer,
    payload,
    disclosed: [],
  });

  // Results follow three rules:
  //  - verified:   a valid signature by a key in the TrustPass issuer registry whose issuer is trusted
  //  - invalid:    the signature does not match, or what was signed was changed (claims, file, issuer)
  //  - unverified: no supported signature to check, or the key is not a trusted registered issuer
  // Nothing is decided from how a document looks or from the issuer name it shows.
  const parts = presentation.trim().split('~');
  const jwt = parts[0] ?? '';
  const disclosures = parts.slice(1).filter((p) => p.length > 0);
  const segments = jwt.split('.');
  if (segments.length !== 3 || !presentation.trim().endsWith('~')) {
    checks.push({ name: 'Format', passed: false, detail: 'Not a TrustPass credential (SD-JWT)' });
    return fail('unverified', 'No supported digital signature was found, so this cannot be verified.');
  }

  let header: { alg?: string; kid?: string };
  let payload: SdJwtPayload;
  try {
    header = decodeSegment(segments[0]!);
    payload = decodeSegment(segments[1]!);
  } catch {
    checks.push({ name: 'Format', passed: false, detail: 'The credential could not be decoded' });
    return fail('unverified', 'No supported digital signature could be read, so this cannot be verified.');
  }
  checks.push({ name: 'Format', passed: true, detail: 'Well-formed SD-JWT' });

  if (header.alg !== 'EdDSA' || !header.kid) {
    checks.push({ name: 'Algorithm', passed: false, detail: `Unsupported algorithm ${String(header.alg)}` });
    return fail('unverified', 'The credential uses a signature algorithm TrustPass cannot check.');
  }

  // The key comes from the registry by its id; never from the credential, its name or its look.
  const issuer = await resolveIssuer(header.kid);
  if (!issuer) {
    checks.push({ name: 'Trusted issuer', passed: false, detail: 'Signing key is not in the TrustPass issuer registry' });
    return fail('unverified', 'The signing key does not belong to a registered issuer, so this cannot be verified.');
  }

  let signatureValid = false;
  try {
    signatureValid = verify(
      null,
      Buffer.from(`${segments[0]}.${segments[1]}`, 'ascii'),
      publicKeyFromJwk(issuer.publicKeyJwk),
      Buffer.from(segments[2]!, 'base64url'),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    checks.push({ name: 'Digital signature', passed: false, detail: 'Ed25519 signature does not match' });
    return fail('invalid', 'The digital signature is invalid: the credential was altered or not signed by this issuer.', issuer, payload);
  }
  checks.push({ name: 'Digital signature', passed: true, detail: 'Valid Ed25519 signature' });

  if (issuer.identifier !== payload.iss) {
    checks.push({ name: 'Trusted issuer', passed: false, detail: 'The issuer named in the credential is not the owner of the signing key' });
    return fail('invalid', 'The issuer named in the credential does not match the signing key.', issuer, payload);
  }
  if (issuer.status !== 'trusted') {
    checks.push({ name: 'Trusted issuer', passed: false, detail: `${issuer.name} is no longer a trusted issuer` });
    return fail('unverified', `The issuer ${issuer.name} has been revoked, so its signatures can no longer be trusted.`, issuer, payload);
  }
  checks.push({ name: 'Trusted issuer', passed: true, detail: `${issuer.name}${issuer.isSimulated ? ' (simulated)' : ''}` });

  const signedDigests = new Set(Array.isArray(payload._sd) ? payload._sd : []);
  const seen = new Set<string>();
  const disclosed: Array<{ name: string; value: ClaimValue }> = [];
  for (const disclosure of disclosures) {
    const digest = disclosureDigest(disclosure);
    if (!signedDigests.has(digest) || seen.has(digest)) {
      checks.push({ name: 'Disclosed claims', passed: false, detail: 'A disclosed claim is not covered by the signature' });
      return fail('invalid', 'A disclosed claim was modified after the issuer signed it.', issuer, payload);
    }
    seen.add(digest);
    try {
      const [, name, value] = decodeSegment<[string, string, ClaimValue]>(disclosure);
      if (typeof name !== 'string') throw new Error('bad name');
      disclosed.push({ name, value });
    } catch {
      checks.push({ name: 'Disclosed claims', passed: false, detail: 'A disclosure could not be decoded' });
      return fail('invalid', 'The credential contains a damaged claim.', issuer, payload);
    }
  }
  checks.push({
    name: 'Disclosed claims',
    passed: true,
    detail: `${disclosed.length} of ${signedDigests.size} signed claims disclosed; the rest stay hidden`,
  });

  if (typeof payload.exp !== 'number' || payload.exp * 1000 <= options.now.getTime()) {
    checks.push({ name: 'Expiry', passed: false, detail: 'The credential has expired' });
    const when = typeof payload.exp === 'number' ? new Date(payload.exp * 1000).toISOString().slice(0, 10) : 'unknown date';
    return { ...fail('invalid', `The credential expired on ${when}.`, issuer, payload), disclosed };
  }
  checks.push({ name: 'Expiry', passed: true, detail: `Valid until ${new Date(payload.exp * 1000).toISOString().slice(0, 10)}` });

  if (options.fileHash !== undefined) {
    if (options.fileHash !== payload.document_hash) {
      checks.push({ name: 'Document integrity', passed: false, detail: 'File hash does not match the signed hash' });
      return { ...fail('invalid', 'The document was modified after the issuer signed it.', issuer, payload), disclosed };
    }
    checks.push({ name: 'Document integrity', passed: true, detail: 'SHA-256 of the file matches the signed hash' });
  }

  return {
    result: 'verified',
    reason: `Signed by ${issuer.name}${issuer.isSimulated ? ' (simulated issuer)' : ''}; signature valid and not expired.`,
    checks,
    issuer,
    payload,
    disclosed,
  };
}

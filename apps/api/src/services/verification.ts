import type { JsonWebKey } from 'node:crypto';
import type { Prisma, VerificationMethod } from '@prisma/client';
import { credentialAad, openString, sha256Hex } from '../lib/crypto';
import { readCredentialIdFromPdf } from '../lib/pdf';
import {
  createPresentation,
  verifySdJwt,
  type IssuerRecordForVerify,
  type SdJwtVerification,
  type VerificationCheck,
} from '../lib/sd-jwt';
import type { AppDeps } from '../types';
import { CLAIM_LABELS } from './issuer';
import { loadDataKey } from './documents';

export function issuerResolver(deps: AppDeps) {
  return async (kid: string): Promise<IssuerRecordForVerify | null> => {
    const issuer = await deps.prisma.issuer.findUnique({ where: { kid } });
    if (!issuer) return null;
    return {
      id: issuer.id,
      name: issuer.name,
      identifier: issuer.identifier,
      status: issuer.status,
      isSimulated: issuer.isSimulated,
      publicKeyJwk: issuer.publicKeyJwk as JsonWebKey,
    };
  };
}

export interface VerificationOutcome {
  /** "expired": a valid signature from a trusted issuer, unchanged document, past its validity period. */
  result: 'verified' | 'invalid' | 'expired' | 'unverified';
  reason: string;
  checks: VerificationCheck[];
  issuer: { id: string; name: string; simulated: boolean; status: string } | null;
  claims: Array<{ key: string; label: string; value: string }>;
  credentialId: string | null;
  documentId: string | null;
  expiresAt: string | null;
}

function toOutcome(v: SdJwtVerification, extra: { documentId?: string | null } = {}): VerificationOutcome {
  return {
    result: v.result,
    reason: v.reason,
    checks: v.checks,
    issuer: v.issuer ? { id: v.issuer.id, name: v.issuer.name, simulated: v.issuer.isSimulated, status: v.issuer.status } : null,
    claims: v.disclosed.map((d) => ({ key: d.name, label: CLAIM_LABELS[d.name] ?? d.name, value: String(d.value) })),
    credentialId: typeof v.payload?.credential_id === 'string' ? v.payload.credential_id : null,
    documentId: extra.documentId ?? null,
    expiresAt: typeof v.payload?.exp === 'number' ? new Date(v.payload.exp * 1000).toISOString() : null,
  };
}

export async function verifyPresentation(deps: AppDeps, presentation: string, fileHash?: string): Promise<VerificationOutcome> {
  const v = await verifySdJwt(presentation, issuerResolver(deps), { now: deps.now(), fileHash });
  return toOutcome(v);
}

/** Decrypt the stored SD-JWT of a credential document (owner or authorised gate only). */
export async function loadStoredCredential(deps: AppDeps, documentId: string, dek?: Buffer): Promise<string> {
  const credential = await deps.prisma.credential.findUnique({ where: { documentId } });
  if (!credential) throw new Error('Credential not found');
  const key = dek ?? (await loadDataKey(deps, documentId));
  try {
    return openString(key, credential.credentialEncrypted, credentialAad(documentId));
  } finally {
    if (!dek) key.fill(0);
  }
}

/** Builds a presentation with only the selected disclosures and verifies it. */
export async function presentAndVerify(deps: AppDeps, sdJwt: string, disclosures: string[]) {
  const presentation = createPresentation(sdJwt, disclosures);
  const outcome = await verifyPresentation(deps, presentation);
  return { presentation, outcome };
}

/** True when a PDF carries its own digital signature field (PAdES / Adobe), a format TrustPass does not check. */
function hasPdfSignature(data: Buffer): boolean {
  if (data.subarray(0, 5).toString('latin1') !== '%PDF-') return false;
  const text = data.toString('latin1');
  return /\/ByteRange\s*\[/.test(text) && /\/Type\s*\/Sig\b|\/FT\s*\/Sig\b/.test(text);
}

const unverifiedFile = (reason: string, detail: string): VerificationOutcome => ({
  result: 'unverified',
  reason,
  checks: [{ name: 'Digital signature', passed: false, detail }],
  issuer: null,
  claims: [],
  credentialId: null,
  documentId: null,
  expiresAt: null,
});

/**
 * Verify an arbitrary file. Only a digital signature decides; the file's look, logo or the
 * issuer name printed on it never does.
 *  - its SHA-256 is bound into a credential: check that credential's signature, issuer and the hash
 *      -> verified, or invalid / unverified as the signature check says
 *  - it names a TrustPass credential but its hash differs: the stored credential's signature is
 *    checked first; only a genuine signed credential makes the file "invalid" (modified)
 *  - anything else: unverified (no supported signature, or no trusted issuer to check against)
 */
export async function verifyFile(deps: AppDeps, data: Buffer): Promise<VerificationOutcome> {
  const fileHash = sha256Hex(data);
  const byHash = await deps.prisma.credential.findFirst({ where: { documentHash: fileHash } });
  if (byHash) {
    const sdJwt = await loadStoredCredential(deps, byHash.documentId);
    const v = await verifySdJwt(createPresentation(sdJwt, []), issuerResolver(deps), { now: deps.now(), fileHash });
    return toOutcome(v, { documentId: byHash.documentId });
  }

  // A credential id inside the file is only a pointer: anyone can type one into a PDF.
  const embeddedId = await readCredentialIdFromPdf(data);
  if (embeddedId) {
    const credential = await deps.prisma.credential.findUnique({ where: { id: embeddedId } });
    if (credential) {
      const sdJwt = await loadStoredCredential(deps, credential.documentId);
      const signed = await verifySdJwt(createPresentation(sdJwt, []), issuerResolver(deps), { now: deps.now() });
      const signatureOk = signed.checks.some((c) => c.name === 'Digital signature' && c.passed);
      const issuerTrusted = signed.checks.some((c) => c.name === 'Trusted issuer' && c.passed);
      if (signatureOk && issuerTrusted) {
        // A genuine credential exists, signed for a different file: this file was changed.
        return {
          ...toOutcome(signed),
          result: 'invalid',
          reason: 'The document was modified after the issuer signed it.',
          checks: [
            ...signed.checks.filter((c) => c.name !== 'Expiry'),
            { name: 'Document integrity', passed: false, detail: 'SHA-256 of this file does not match the hash the issuer signed' },
          ],
          claims: [],
        };
      }
      // The credential it points to cannot itself be verified (revoked issuer or broken signature).
      return { ...toOutcome(signed), result: 'unverified', reason: `This file cannot be verified: ${signed.reason.charAt(0).toLowerCase()}${signed.reason.slice(1)}`, claims: [] };
    }
  }

  if (hasPdfSignature(data)) {
    return unverifiedFile(
      'This PDF has a digital signature in a format TrustPass cannot check (PDF signatures). Check it in a PDF reader that validates signatures.',
      'PDF signature found; TrustPass checks only credentials from issuers in its registry',
    );
  }

  return unverifiedFile(
    'No supported digital signature was found. A file alone, however it looks, does not prove it is authentic.',
    'No signed credential from a registered issuer matches this file',
  );
}

export async function recordVerification(
  deps: AppDeps,
  outcome: VerificationOutcome,
  context: {
    method: VerificationMethod;
    userId?: string | null;
    orgId?: string | null;
    linkId?: string | null;
    documentId?: string | null;
  },
) {
  // The stored result field has three values (verified, invalid, unverified). An expired check is
  // kept as "unverified" there, with its failed Expiry check in `checks`; displayResult() reads it
  // back as "expired". This avoids a database change.
  const credentialExists = outcome.credentialId
    ? await deps.prisma.credential.findUnique({ where: { id: outcome.credentialId }, select: { id: true } })
    : null;
  return deps.prisma.verificationRecord.create({
    data: {
      result: outcome.result === 'expired' ? 'unverified' : outcome.result,
      method: context.method,
      reason: outcome.reason,
      checks: outcome.checks as unknown as Prisma.InputJsonValue,
      documentId: context.documentId ?? outcome.documentId ?? null,
      credentialId: credentialExists ? outcome.credentialId : null,
      linkId: context.linkId ?? null,
      issuerId: outcome.issuer?.id ?? null,
      verifiedByUserId: context.userId ?? null,
      verifiedByOrgId: context.orgId ?? null,
    },
  });
}

/** The result to show for a stored verification record (see recordVerification for "expired"). */
export function displayResult(record: { result: 'verified' | 'invalid' | 'unverified'; checks: unknown }): VerificationOutcome['result'] {
  if (record.result !== 'unverified' || !Array.isArray(record.checks)) return record.result;
  const checks = record.checks as Array<{ name?: string; passed?: boolean }>;
  const signed = checks.some((c) => c.name === 'Digital signature' && c.passed === true);
  const trusted = checks.some((c) => c.name === 'Trusted issuer' && c.passed === true);
  const expired = checks.some((c) => c.name === 'Expiry' && c.passed === false && /^Expired on/.test(String((c as { detail?: string }).detail ?? '')));
  return signed && trusted && expired ? 'expired' : 'unverified';
}

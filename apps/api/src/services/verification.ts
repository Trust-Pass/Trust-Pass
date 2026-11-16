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
  result: 'verified' | 'invalid' | 'unverified';
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

/**
 * Verify an arbitrary file:
 *  - its SHA-256 matches a credential signed by a trusted issuer -> check that credential
 *  - it carries a TrustPass credential id but the hash differs   -> Invalid (modified)
 *  - neither                                                     -> Unverified
 */
export async function verifyFile(deps: AppDeps, data: Buffer): Promise<VerificationOutcome> {
  const fileHash = sha256Hex(data);
  const byHash = await deps.prisma.credential.findFirst({ where: { documentHash: fileHash } });
  if (byHash) {
    const sdJwt = await loadStoredCredential(deps, byHash.documentId);
    const v = await verifySdJwt(createPresentation(sdJwt, []), issuerResolver(deps), { now: deps.now(), fileHash });
    return toOutcome(v, { documentId: byHash.documentId });
  }

  const embeddedId = await readCredentialIdFromPdf(data);
  if (embeddedId) {
    const credential = await deps.prisma.credential.findUnique({ where: { id: embeddedId }, include: { issuer: true } });
    if (credential) {
      return {
        result: 'invalid',
        reason: 'The document was modified after the issuer signed it.',
        checks: [
          { name: 'Format', passed: true, detail: 'TrustPass certificate' },
          { name: 'Trusted issuer', passed: true, detail: credential.issuer.name },
          { name: 'Document integrity', passed: false, detail: 'SHA-256 of the file does not match the signed hash' },
        ],
        issuer: {
          id: credential.issuer.id,
          name: credential.issuer.name,
          simulated: credential.issuer.isSimulated,
          status: credential.issuer.status,
        },
        claims: [],
        credentialId: credential.id,
        documentId: null,
        expiresAt: credential.expiresAt.toISOString(),
      };
    }
  }

  return {
    result: 'unverified',
    reason: 'No trusted issuer signature was found for this file. An uploaded file alone does not prove it is authentic.',
    checks: [{ name: 'Trusted issuer', passed: false, detail: 'No signed credential matches this file' }],
    issuer: null,
    claims: [],
    credentialId: null,
    documentId: null,
    expiresAt: null,
  };
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
  const credentialExists = outcome.credentialId
    ? await deps.prisma.credential.findUnique({ where: { id: outcome.credentialId }, select: { id: true } })
    : null;
  return deps.prisma.verificationRecord.create({
    data: {
      result: outcome.result,
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

import { randomInt, randomUUID } from 'node:crypto';
import type { Issuer, User } from '@prisma/client';
import { credentialAad, seal, sha256Hex } from '../lib/crypto';
import { AppError } from '../lib/errors';
import { renderCertificate } from '../lib/pdf';
import { ed25519FromSeed, issueSdJwt, jwkThumbprint, publicKeyToJwk } from '../lib/sd-jwt';
import type { AppDeps } from '../types';
import { notify } from './audit';
import { storeEncryptedDocument } from './documents';
import { getSettings } from './settings';

/**
 * The simulated trusted issuer. It plays the role of an outside university:
 * it has its own Ed25519 key (derived from ISSUER_SIGNING_SEED) and signs
 * credentials. Verification code never uses this private key; it only reads
 * the public key from the issuers table.
 */
export const DEMO_ISSUER = {
  name: 'TrustPass Demo University',
  identifier: 'trustpass:issuer:demo-university',
  vct: 'TrustPassEnrollmentCredential',
};

export const CLAIM_LABELS: Record<string, string> = {
  full_name: 'Full name',
  student_id: 'Student ID',
  university: 'University',
  program: 'Program',
  enrollment_status: 'Enrollment status',
  academic_year: 'Academic year',
};

function issuerKeys(deps: AppDeps) {
  const { privateKey, publicKey } = ed25519FromSeed(deps.config.issuerSeed);
  const jwk = publicKeyToJwk(publicKey);
  return { privateKey, jwk, kid: jwkThumbprint(jwk) };
}

/** Registers (or refreshes) the demo issuer's public key in the trusted registry. */
export async function ensureDemoIssuer(deps: AppDeps): Promise<Issuer> {
  const { jwk, kid } = issuerKeys(deps);
  const existing = await deps.prisma.issuer.findUnique({ where: { identifier: DEMO_ISSUER.identifier } });
  if (existing) {
    if (existing.kid === kid) return existing;
    // The signing seed changed: the old key can no longer be used, register the new one.
    return deps.prisma.issuer.update({
      where: { id: existing.id },
      data: { kid, publicKeyJwk: jwk as object },
    });
  }
  return deps.prisma.issuer.create({
    data: {
      name: DEMO_ISSUER.name,
      identifier: DEMO_ISSUER.identifier,
      kid,
      publicKeyJwk: jwk as object,
      status: 'trusted',
      isSimulated: true,
    },
  });
}

function academicYear(date: Date) {
  const y = date.getUTCFullYear();
  return date.getUTCMonth() >= 7 ? `${y}/${y + 1}` : `${y - 1}/${y}`;
}

export async function issueEnrollmentCredential(
  deps: AppDeps,
  holder: User,
  input: { nameOnCertificate: string; program: string },
) {
  const { prisma, now } = deps;
  const settings = await getSettings(prisma);
  const existing = await prisma.credential.count({ where: { document: { ownerId: holder.id, deletedAt: null } } });
  if (existing >= settings.credentialsPerUser) {
    throw new AppError(
      409,
      'credential_limit',
      `You already hold ${existing} demo credentials, the limit for this demo. Delete one to request another.`,
    );
  }

  const issuer = await ensureDemoIssuer(deps);
  if (issuer.status !== 'trusted') {
    throw new AppError(409, 'issuer_revoked', 'The demo university is currently not trusted, so it cannot issue credentials.');
  }
  const { privateKey, kid } = issuerKeys(deps);

  const credentialId = randomUUID();
  const issuedAt = now();
  const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1000);
  const studentId = `4${String(randomInt(0, 100_000_000)).padStart(8, '0')}`;
  const claims = {
    full_name: input.nameOnCertificate,
    student_id: studentId,
    university: DEMO_ISSUER.name,
    program: input.program,
    enrollment_status: 'Active',
    academic_year: academicYear(issuedAt),
  };

  const pdf = await renderCertificate({
    credentialId,
    universityName: DEMO_ISSUER.name,
    fullName: claims.full_name,
    studentId,
    program: claims.program,
    enrollmentStatus: claims.enrollment_status,
    academicYear: claims.academic_year,
    issuedAt,
    expiresAt,
  });
  const documentHash = sha256Hex(pdf);

  const issued = issueSdJwt({
    privateKey,
    kid,
    issuer: DEMO_ISSUER.identifier,
    vct: DEMO_ISSUER.vct,
    credentialId,
    documentHash,
    issuedAt,
    expiresAt,
    claims: Object.entries(claims).map(([name, value]) => ({ name, value })),
  });

  const document = await storeEncryptedDocument(deps, {
    ownerId: holder.id,
    title: `Enrollment Certificate - ${DEMO_ISSUER.name}`,
    category: 'enrollment_certificate',
    kind: 'credential',
    mimeType: 'application/pdf',
    data: pdf,
    claims: issued.disclosures.map((d) => ({
      key: d.name,
      label: CLAIM_LABELS[d.name] ?? d.name,
      value: String(d.value),
      source: 'issuer' as const,
      disclosure: d.disclosure,
    })),
    extra: async (tx, documentId, dek) => {
      await tx.credential.create({
        data: {
          id: credentialId,
          documentId,
          issuerId: issuer.id,
          format: 'sd-jwt',
          credentialEncrypted: seal(dek, issued.sdJwt, credentialAad(documentId)),
          documentHash,
          issuedAt,
          expiresAt,
        },
      });
    },
  });

  await notify(prisma, {
    userId: holder.id,
    type: 'credential_issued',
    title: 'New credential from TrustPass Demo University',
    body: 'Your enrollment certificate was issued and digitally signed. You can now share selected fields from it.',
    documentId: document.id,
  });
  return document;
}

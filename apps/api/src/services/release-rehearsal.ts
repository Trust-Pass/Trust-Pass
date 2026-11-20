import { createHash, randomBytes } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import type { FastifyInstance } from 'fastify';
import { PDFDocument } from 'pdf-lib';
import { hashToken, sha256Hex } from '../lib/crypto';
import type { GeoProvider } from '../lib/geo';
import { decryptToken } from '../modules/sharing';
import type { AppDeps } from '../types';
import { decryptClaims, loadDataKey, readDocumentFile } from './documents';
import { openRecipientLabel, openTitle } from './metadata';
import { loadStoredCredential, presentAndVerify } from './verification';

/**
 * Release rehearsal on a RESTORED COPY of production (never on production itself).
 *
 * Reads every document, field, credential and share link through the application's own code,
 * before and after the metadata backfill, and proves they are unchanged. Everything that is
 * compared leaves this module only as a SHA-256 digest or a count: no title, name, field value,
 * token or file content is ever returned, printed or written.
 *
 * Used by scripts/rehearsal/trustpass-release-rehearsal.sh through src/scripts/rehearsal.ts.
 */

export interface Failure {
  /** First 8 characters of the document or link id. */
  ref: string;
  stage: string;
}

export interface DocumentSnapshot {
  /** documentId -> digest of everything readable about the document. */
  digests: Map<string, string>;
  counts: { documents: number; files: number; fields: number; credentials: number; credentialsVerified: number; links: number };
  failures: Failure[];
}

const ref = (id: string) => id.slice(0, 8);
const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

/** Opens every active document the way the owner's pages do; returns digests only. */
export async function snapshotDocuments(deps: AppDeps): Promise<DocumentSnapshot> {
  const { prisma } = deps;
  const result: DocumentSnapshot = {
    digests: new Map(),
    counts: { documents: 0, files: 0, fields: 0, credentials: 0, credentialsVerified: 0, links: 0 },
    failures: [],
  };
  const documents = await prisma.document.findMany({
    where: { deletedAt: null },
    include: { claims: true, links: { orderBy: { id: 'asc' } }, credential: { select: { documentId: true } } },
    orderBy: { id: 'asc' },
  });
  for (const doc of documents) {
    result.counts.documents++;
    let dek: Buffer;
    try {
      dek = await loadDataKey(deps, doc.id);
    } catch {
      result.failures.push({ ref: ref(doc.id), stage: 'document key' });
      continue;
    }
    try {
      const parts: Record<string, unknown> = { title: openTitle(dek, doc), mime: doc.mimeType, size: doc.sizeBytes };
      try {
        const file = await readDocumentFile(deps, doc, dek); // checks GCM and the sealed SHA-256
        parts.file = sha256Hex(file);
        file.fill(0);
        result.counts.files++;
      } catch {
        result.failures.push({ ref: ref(doc.id), stage: 'file' });
      }
      try {
        // Keyed by claim id, not by claim key: the backfill renames keys but never changes ids.
        parts.fields = decryptClaims(dek, doc.id, doc.claims)
          .map((c) => ({ id: c.id, label: c.label, value: c.value, disclosure: c.disclosure, source: c.source }))
          .sort((a, b) => a.id.localeCompare(b.id));
        result.counts.fields += doc.claims.length;
      } catch {
        result.failures.push({ ref: ref(doc.id), stage: 'fields' });
      }
      if (doc.credential) {
        result.counts.credentials++;
        try {
          const sdJwt = await loadStoredCredential(deps, doc.id, dek);
          parts.credential = sha256Hex(sdJwt);
          const disclosures = decryptClaims(dek, doc.id, doc.claims)
            .map((c) => c.disclosure)
            .filter((d): d is string => Boolean(d));
          const { outcome } = await presentAndVerify(deps, sdJwt, disclosures);
          parts.credentialResult = outcome.result;
          if (outcome.result === 'verified') result.counts.credentialsVerified++;
          else result.failures.push({ ref: ref(doc.id), stage: `credential ${outcome.result}` });
        } catch {
          result.failures.push({ ref: ref(doc.id), stage: 'credential' });
        }
      }
      parts.links = doc.links.map((l) => ({ id: l.id, recipient: openRecipientLabel(dek, l) }));
      result.counts.links += doc.links.length;
      result.digests.set(doc.id, digest(parts));
    } finally {
      dek.fill(0);
    }
  }
  return result;
}

export function compareSnapshots(before: DocumentSnapshot, after: DocumentSnapshot): { same: number; changed: Failure[] } {
  const changed: Failure[] = [];
  let same = 0;
  for (const [id, d] of before.digests) {
    const a = after.digests.get(id);
    if (a === undefined) changed.push({ ref: ref(id), stage: 'missing after backfill' });
    else if (a !== d) changed.push({ ref: ref(id), stage: 'content differs after backfill' });
    else same++;
  }
  for (const id of after.digests.keys()) if (!before.digests.has(id)) changed.push({ ref: ref(id), stage: 'new after backfill' });
  return { same, changed };
}

/**
 * Digest of every stored ciphertext and wrapped key. Must be identical at the start and the end:
 * the release may re-encrypt metadata, but files and document keys are only read.
 */
export async function ciphertextFingerprint(deps: AppDeps): Promise<{ digest: string; files: number; keys: number }> {
  const documents = await deps.prisma.document.findMany({
    select: { id: true, storageKey: true, encIv: true, encTag: true, deletedAt: true },
    orderBy: { id: 'asc' },
  });
  const keys = await deps.prisma.documentKey.findMany({ orderBy: { documentId: 'asc' } });
  const hash = createHash('sha256');
  let files = 0;
  for (const d of documents) {
    hash.update(`${d.id}|${d.storageKey}|${Buffer.from(d.encIv).toString('hex')}|${Buffer.from(d.encTag).toString('hex')}|`);
    if (d.deletedAt) continue;
    try {
      hash.update(sha256Hex(await deps.storage.get(d.storageKey)));
      files++;
    } catch {
      hash.update('missing');
    }
  }
  for (const k of keys) {
    hash.update(`${k.documentId}|${k.kekVersion}|${Buffer.from(k.wrappedDek).toString('hex')}|${Buffer.from(k.wrapIv).toString('hex')}|${Buffer.from(k.wrapTag).toString('hex')}|`);
  }
  return { digest: hash.digest('hex'), files, keys: keys.length };
}

/** A geo provider whose answer the rehearsal sets before each request. */
export class RehearsalGeo implements GeoProvider {
  readonly name = 'simulated' as const;
  country: string | null = 'SA';
  lookup(): string | null {
    return this.country;
  }
}

export interface LinkReport {
  links: number;
  tokensRecovered: number;
  /** Revoked links, or links of deleted documents: must answer 410. */
  endedRefused: number;
  /** Links already expired today: must answer 410 at today's date. */
  expiredRefusedToday: number;
  /** Every link that was usable once, opened as of its creation time. */
  viewsOk: number;
  filesOk: number;
  /** Existing links must all have downloads OFF after the release. */
  downloadsOffByDefault: boolean;
  downloadsOk: number;
  skipped: Failure[];
  failures: Failure[];
}

/**
 * Opens every share link through the real HTTP routes (access gate included):
 *  - revoked links and links of deleted documents must be refused (410);
 *  - links that have expired by today must be refused today, and still open as of their creation
 *    time (proving the data behind them is intact);
 *  - each view must show the same title, the permitted number of fields and, for credentials, a
 *    verified result; shared files must come back as a watermarked PDF;
 *  - downloads: OFF on every existing link; then, on this throw-away copy only, each link that
 *    shares the file is switched on and one watermarked copy is downloaded and parsed.
 * Organization links are opened as an active member, through a session created in the copy.
 */
export async function checkShareLinks(
  deps: AppDeps,
  app: FastifyInstance,
  clock: { now: Date },
  geo: RehearsalGeo,
  realNow: Date,
): Promise<LinkReport> {
  const { prisma } = deps;
  const report: LinkReport = {
    links: 0,
    tokensRecovered: 0,
    endedRefused: 0,
    expiredRefusedToday: 0,
    viewsOk: 0,
    filesOk: 0,
    downloadsOffByDefault: false,
    downloadsOk: 0,
    skipped: [],
    failures: [],
  };
  report.downloadsOffByDefault = (await prisma.sharingLink.count({ where: { allowDownload: true } })) === 0;

  const links = await prisma.sharingLink.findMany({
    include: {
      document: { include: { claims: true } },
      countries: true,
      permissions: true,
      recipientOrg: { select: { id: true, status: true } },
    },
    orderBy: { id: 'asc' },
  });

  for (const link of links) {
    report.links++;
    const r = ref(link.id);
    let token: string;
    try {
      token = decryptToken(deps, link.id, link.tokenEncrypted);
    } catch {
      report.failures.push({ ref: r, stage: 'link copy does not open' });
      continue;
    }
    if (hashToken(token) !== link.tokenHash) {
      report.failures.push({ ref: r, stage: 'link copy does not match its hash' });
      continue;
    }
    report.tokensRecovered++;

    geo.country = link.countries[0]?.countryCode ?? 'SA';
    let cookie: string | undefined;
    if (link.recipientType === 'organization') {
      const member = link.recipientOrgId
        ? await prisma.organizationMember.findFirst({ where: { orgId: link.recipientOrgId, user: { status: 'active' } }, select: { userId: true } })
        : null;
      if (!member || link.recipientOrg?.status !== 'active') {
        report.skipped.push({ ref: r, stage: 'organization link: no active organization or member' });
        continue;
      }
      cookie = await sessionCookie(deps, member.userId);
    }
    // One address per link: per-address rate limits never mix links (TEST-NET-2, never routed).
    const address = `198.51.${Math.floor(report.links / 250) % 250}.${(report.links % 250) + 1}`;
    const get = (path: string) =>
      app.inject({ method: 'GET', url: `/api/share/${token}${path}`, remoteAddress: address, ...(cookie ? { cookies: { [deps.config.cookieName]: cookie } } : {}) });

    // 1. Ended links stay ended.
    if (link.revokedAt || link.document.deletedAt) {
      clock.now = realNow;
      const res = await get('');
      if (res.statusCode === 410) report.endedRefused++;
      else report.failures.push({ ref: r, stage: `ended link answered ${res.statusCode}` });
      continue;
    }
    // 2. Expired by today: refused today.
    if (link.expiresAt <= realNow) {
      clock.now = realNow;
      const res = await get('');
      if (res.statusCode === 410) report.expiredRefusedToday++;
      else report.failures.push({ ref: r, stage: `expired link answered ${res.statusCode}` });
    }

    // 3. As of creation time, the link opens and shows the right content.
    clock.now = new Date(link.createdAt.getTime() + 60_000);
    if (clock.now >= link.expiresAt) clock.now = new Date(link.createdAt.getTime() + 1_000);
    const view = await get('');
    if (view.statusCode !== 200) {
      report.failures.push({ ref: r, stage: `view answered ${view.statusCode}` });
      continue;
    }
    const body = view.json() as { document: { title: string; fileShared: boolean; downloadAllowed?: boolean }; fields: unknown[]; verification: { result: string } };
    const dek = await loadDataKey(deps, link.documentId);
    const expectedTitle = openTitle(dek, link.document);
    dek.fill(0);
    const titleOk = body.document.title === expectedTitle;
    const fieldsOk =
      link.document.kind === 'credential' ? body.verification.result === 'verified' : body.fields.length === link.permissions.length;
    if (!titleOk || !fieldsOk || body.document.downloadAllowed !== false) {
      report.failures.push({ ref: r, stage: !titleOk ? 'view title differs' : !fieldsOk ? 'view fields differ' : 'download not off by default' });
      continue;
    }
    report.viewsOk++;

    if (!link.includeFile) continue;
    const file = await get('/file');
    if (file.statusCode !== 200 || file.rawPayload.subarray(0, 5).toString('latin1') !== '%PDF-') {
      report.failures.push({ ref: r, stage: `file answered ${file.statusCode}` });
      continue;
    }
    report.filesOk++;

    // 4. Recipient download, switched on for this link in the throw-away copy only.
    await prisma.sharingLink.update({ where: { id: link.id }, data: { allowDownload: true } });
    const dl = await get('/download');
    await prisma.sharingLink.update({ where: { id: link.id }, data: { allowDownload: false } });
    if (dl.statusCode !== 200) {
      report.failures.push({ ref: r, stage: `download answered ${dl.statusCode}` });
      continue;
    }
    try {
      const pdf = await PDFDocument.load(dl.rawPayload);
      const expectedPages = link.document.mimeType === 'application/pdf' ? await pageCountOf(deps, link.document) : 1;
      const stamped = pdfText(dl.rawPayload).includes(hexOf('CONFIDENTIAL - Downloaded for: '));
      if (pdf.getPageCount() === expectedPages && stamped && String(dl.headers['x-trustpass-copy'] ?? '').length === 10) report.downloadsOk++;
      else report.failures.push({ ref: r, stage: 'downloaded copy is not the expected watermarked PDF' });
    } catch {
      report.failures.push({ ref: r, stage: 'downloaded copy does not parse' });
    }
  }
  clock.now = realNow;
  return report;
}

async function sessionCookie(deps: AppDeps, userId: string): Promise<string> {
  return (await createSession(deps, userId)).token;
}

/** A session in the throw-away copy, valid at any rehearsal clock time. */
async function createSession(deps: AppDeps, userId: string): Promise<{ token: string; csrf: string }> {
  const token = randomBytes(32).toString('base64url');
  const csrf = randomBytes(16).toString('hex');
  const now = new Date(0);
  await deps.prisma.session.create({
    data: {
      userId,
      tokenHash: hashToken(token),
      csrfToken: csrf,
      createdAt: now,
      lastSeenAt: new Date('2999-01-01T00:00:00Z'),
      expiresAt: new Date('2999-01-01T00:00:00Z'),
    },
  });
  return { token, csrf };
}

export interface ProbeReport {
  /** Active documents whose owner account is active. */
  documents: number;
  linksCreated: number;
  viewsOk: number;
  filesOk: number;
  downloadsOk: number;
  skipped: Failure[];
  failures: Failure[];
}

/**
 * Real files through the recipient path, on the throw-away copy only. Existing links may all have
 * ended, so for every active document the rehearsal signs in as its owner (a session created in the
 * copy), creates a new link through the real API (every field, the file, downloads allowed, 1 hour)
 * and opens it as an anonymous recipient: the view must show every field (or a verified credential),
 * the file must come back as a watermarked PDF, and one downloaded copy must parse with the original's
 * page count and the recipient stamp. This exercises link creation, the access gate, decryption,
 * watermarking and the download builder on the real documents.
 */
export async function probeDocuments(deps: AppDeps, app: FastifyInstance, clock: { now: Date }, geo: RehearsalGeo, realNow: Date): Promise<ProbeReport> {
  const { prisma } = deps;
  const report: ProbeReport = { documents: 0, linksCreated: 0, viewsOk: 0, filesOk: 0, downloadsOk: 0, skipped: [], failures: [] };
  clock.now = realNow;
  geo.country = 'SA';
  const documents = await prisma.document.findMany({
    where: { deletedAt: null },
    include: { claims: { select: { id: true } }, owner: { select: { id: true, status: true } } },
    orderBy: { id: 'asc' },
  });
  let n = 0;
  for (const doc of documents) {
    const r = ref(doc.id);
    if (doc.owner.status !== 'active') {
      report.skipped.push({ ref: r, stage: 'owner account not active' });
      continue;
    }
    report.documents++;
    n++;
    const session = await createSession(deps, doc.owner.id);
    const create = await app.inject({
      method: 'POST',
      url: `/api/documents/${doc.id}/links`,
      cookies: { [deps.config.cookieName]: session.token },
      headers: { 'x-csrf-token': session.csrf },
      remoteAddress: `198.18.${Math.floor(n / 250) % 250}.${(n % 250) + 1}`,
      payload: {
        claimIds: doc.claims.map((c) => c.id),
        includeFile: true,
        // Watermarks are optional (off by default); the probe checks the watermarked download path.
        watermark: { enabled: true },
        allowDownload: true,
        recipientType: 'anyone',
        recipientLabel: 'Rehearsal check',
        expiresIn: '1h',
        allowedCountries: [],
      },
    });
    if (create.statusCode !== 201) {
      report.failures.push({ ref: r, stage: `creating a link answered ${create.statusCode}` });
      continue;
    }
    report.linksCreated++;
    const token = String((create.json() as { url: string }).url).split('/s/')[1] ?? '';
    const address = `198.19.${Math.floor(n / 250) % 250}.${(n % 250) + 1}`;
    const get = (path: string) => app.inject({ method: 'GET', url: `/api/share/${token}${path}`, remoteAddress: address });

    const view = await get('');
    if (view.statusCode !== 200) {
      report.failures.push({ ref: r, stage: `probe view answered ${view.statusCode}` });
      continue;
    }
    const body = view.json() as { document: { title: string; downloadAllowed?: boolean }; fields: unknown[]; verification: { result: string } };
    const dek = await loadDataKey(deps, doc.id);
    const titleOk = body.document.title === openTitle(dek, doc);
    dek.fill(0);
    const fieldsOk = doc.kind === 'credential' ? body.verification.result === 'verified' : body.fields.length === doc.claims.length;
    if (!titleOk || !fieldsOk || body.document.downloadAllowed !== true) {
      report.failures.push({ ref: r, stage: !titleOk ? 'probe view title differs' : !fieldsOk ? 'probe view fields differ' : 'probe download not offered' });
      continue;
    }
    report.viewsOk++;

    const file = await get('/file');
    if (file.statusCode !== 200 || file.rawPayload.subarray(0, 5).toString('latin1') !== '%PDF-') {
      report.failures.push({ ref: r, stage: `probe file answered ${file.statusCode}` });
      continue;
    }
    report.filesOk++;

    const dl = await get('/download');
    if (dl.statusCode !== 200) {
      report.failures.push({ ref: r, stage: `probe download answered ${dl.statusCode}` });
      continue;
    }
    try {
      const pdf = await PDFDocument.load(dl.rawPayload);
      const expectedPages = doc.mimeType === 'application/pdf' ? await pageCountOf(deps, doc) : 1;
      const stamped = pdfText(dl.rawPayload).includes(hexOf('CONFIDENTIAL - Downloaded for: Rehearsal check'));
      if (pdf.getPageCount() === expectedPages && stamped) report.downloadsOk++;
      else report.failures.push({ ref: r, stage: 'probe download is not the expected watermarked PDF' });
    } catch {
      report.failures.push({ ref: r, stage: 'probe download does not parse' });
    }
  }
  return report;
}

async function pageCountOf(deps: AppDeps, document: Parameters<typeof readDocumentFile>[1]): Promise<number> {
  const data = await readDocumentFile(deps, document);
  try {
    return (await PDFDocument.load(data, { updateMetadata: false })).getPageCount();
  } finally {
    data.fill(0);
  }
}

const hexOf = (text: string) => Buffer.from(text, 'latin1').toString('hex').toUpperCase();

/** Page content streams of a PDF as text (pdf-lib writes Helvetica text as hex strings). */
function pdfText(pdf: Buffer): string {
  const raw = pdf.toString('latin1');
  let out = raw;
  const re = /stream\r?\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const start = m.index + m[0].length;
    const end = raw.indexOf('endstream', start);
    if (end < 0) break;
    try {
      out += inflateSync(pdf.subarray(start, end)).toString('latin1');
    } catch {
      /* not a Flate stream */
    }
  }
  return out;
}

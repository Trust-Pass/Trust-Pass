import { degrees, PDFDict, PDFDocument, PDFName, rgb, StandardFonts, type PDFFont, type PDFPage, type RGB } from 'pdf-lib';
import { DEFAULT_WATERMARK, type WatermarkColor, type WatermarkSettings, type WatermarkStrength } from '@trustpass/shared';

const NAVY = rgb(0.043, 0.106, 0.231);
const TEAL = rgb(0.078, 0.722, 0.651);
const INK = rgb(0.12, 0.14, 0.2);
const MUTED = rgb(0.42, 0.45, 0.52);

/**
 * Standard PDF fonts only cover Latin characters (WinAnsi). Anything else is
 * replaced so drawing never throws; callers validate names beforehand.
 */
export function toWinAnsi(text: string): string {
  return text
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^\x20-\x7E–]/g, '?');
}

/** Use a readable fallback when most of a label is outside the Latin alphabet. */
export function watermarkSafe(text: string, fallback: string): string {
  const converted = toWinAnsi(text).trim();
  const unknown = (converted.match(/\?/g) ?? []).length;
  return converted.length === 0 || unknown > converted.length / 3 ? fallback : converted;
}

export interface CertificateData {
  credentialId: string;
  universityName: string;
  fullName: string;
  studentId: string;
  program: string;
  enrollmentStatus: string;
  academicYear: string;
  issuedAt: Date;
  expiresAt: Date;
}

const fmtDate = (d: Date) =>
  d.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'UTC' });

function centered(page: PDFPage, text: string, y: number, font: PDFFont, size: number, color = INK) {
  const width = font.widthOfTextAtSize(text, size);
  page.drawText(text, { x: (page.getWidth() - width) / 2, y, size, font, color });
}

/** The PDF certificate the simulated issuer signs. Its SHA-256 goes into the signed credential. */
export async function renderCertificate(data: CertificateData): Promise<Buffer> {
  const pdf = await PDFDocument.create();
  pdf.setTitle(`Certificate of Enrollment - ${toWinAnsi(data.fullName)}`);
  pdf.setAuthor(data.universityName);
  pdf.setSubject('TrustPass verifiable credential (simulated issuer)');
  pdf.setKeywords(['trustpass', `trustpass-credential:${data.credentialId}`]);
  pdf.setProducer('TrustPass Demo Issuer');
  pdf.setCreator('TrustPass');
  pdf.setCreationDate(data.issuedAt);
  pdf.setModificationDate(data.issuedAt);

  const page = pdf.addPage([595.28, 841.89]);
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const serif = await pdf.embedFont(StandardFonts.TimesRomanBold);
  const { width, height } = page.getSize();

  page.drawRectangle({ x: 0, y: height - 130, width, height: 130, color: NAVY });
  page.drawRectangle({ x: 0, y: height - 136, width, height: 6, color: TEAL });
  centered(page, toWinAnsi(data.universityName).toUpperCase(), height - 62, bold, 20, rgb(1, 1, 1));
  centered(page, 'Simulated issuer for TrustPass demonstrations', height - 88, regular, 11, rgb(0.8, 0.86, 0.95));

  centered(page, 'Certificate of Enrollment', height - 210, serif, 30, NAVY);
  centered(page, 'This is to certify that', height - 258, regular, 12, MUTED);
  centered(page, toWinAnsi(data.fullName), height - 296, serif, 26, INK);
  centered(page, 'is enrolled as a student in', height - 330, regular, 12, MUTED);
  centered(page, toWinAnsi(data.program), height - 362, bold, 18, INK);

  const rows: Array<[string, string]> = [
    ['Student ID', data.studentId],
    ['Enrollment status', data.enrollmentStatus],
    ['Academic year', data.academicYear],
    ['Issued on', fmtDate(data.issuedAt)],
    ['Valid until', fmtDate(data.expiresAt)],
    ['Credential ID', data.credentialId],
  ];
  let y = height - 430;
  page.drawLine({ start: { x: 90, y: y + 22 }, end: { x: width - 90, y: y + 22 }, thickness: 0.8, color: rgb(0.85, 0.87, 0.9) });
  for (const [label, value] of rows) {
    page.drawText(label, { x: 110, y, size: 11, font: regular, color: MUTED });
    page.drawText(toWinAnsi(value), { x: 260, y, size: 11, font: bold, color: INK });
    y -= 26;
  }
  page.drawLine({ start: { x: 90, y: y + 8 }, end: { x: width - 90, y: y + 8 }, thickness: 0.8, color: rgb(0.85, 0.87, 0.9) });

  page.drawRectangle({ x: 90, y: 120, width: width - 180, height: 70, borderColor: TEAL, borderWidth: 1.2, color: rgb(0.93, 0.99, 0.98) });
  page.drawText('Digitally signed with Ed25519 by the issuer.', { x: 108, y: 166, size: 11, font: bold, color: NAVY });
  page.drawText('Any change to this file breaks the signature. Verify it on the TrustPass', { x: 108, y: 148, size: 9.5, font: regular, color: INK });
  page.drawText('Verification page to confirm it is authentic and unmodified.', { x: 108, y: 135, size: 9.5, font: regular, color: INK });

  centered(page, 'SIMULATED CREDENTIAL - not issued by a real institution. For demonstration only.', 70, bold, 9, rgb(0.75, 0.2, 0.2));

  return Buffer.from(await pdf.save({ useObjectStreams: false }));
}

/** Reads the credential id embedded in a TrustPass certificate's metadata, if any. */
export async function readCredentialIdFromPdf(data: Buffer): Promise<string | null> {
  try {
    const pdf = await PDFDocument.load(data, { updateMetadata: false, ignoreEncryption: true });
    const keywords = pdf.getKeywords() ?? '';
    const match = keywords.match(/trustpass-credential:([0-9a-f-]{36})/i);
    return match?.[1]?.toLowerCase() ?? null;
  } catch {
    return null;
  }
}

export interface WatermarkInfo {
  recipient: string;
  viewedAt: Date;
  linkRef: string;
  /** Set for downloads: a per-download reference that ties a leaked copy to one logged event. */
  download?: { copyRef: string; downloadedBy?: string };
  /** The owner's choice for this link. Missing = the standard watermark. enabled: false = none drawn. */
  look?: WatermarkSettings;
}

const WATERMARK_COLORS: Record<WatermarkColor, RGB> = {
  navy: NAVY,
  teal: rgb(0.03, 0.42, 0.39),
  crimson: rgb(0.55, 0.06, 0.12),
  gray: rgb(0.3, 0.32, 0.36),
};
/** Opacity of the diagonal stamp and of the name bands, per strength. "light" is the original look. */
const WATERMARK_STRENGTH: Record<WatermarkStrength, { stamp: number; band: number }> = {
  light: { stamp: 0.09, band: 0.82 },
  medium: { stamp: 0.16, band: 0.88 },
  strong: { stamp: 0.26, band: 0.94 },
};

/** True when recipient copies of this link get a visible watermark. */
export function watermarkOn(info: Pick<WatermarkInfo, 'look'>): boolean {
  return (info.look ?? DEFAULT_WATERMARK).enabled;
}

function watermarkPage(page: PDFPage, font: PDFFont, bold: PDFFont, info: WatermarkInfo) {
  const look = info.look ?? DEFAULT_WATERMARK;
  if (!look.enabled) return;
  const color = WATERMARK_COLORS[look.color];
  const strength = WATERMARK_STRENGTH[look.strength];
  const { width, height } = page.getSize();
  if (look.style !== 'bands') drawStamps(page, bold, watermarkSafe(look.text, 'CONFIDENTIAL'), color, strength.stamp);
  if (look.style === 'diagonal') return;

  const when = `${info.viewedAt.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  const lines = recipientLines(info, when);
  const textSize = Math.max(6.5, Math.min(9, width / 70));
  const bandHeight = textSize * 2 + 14;
  page.drawRectangle({ x: 0, y: height - bandHeight, width, height: bandHeight, color, opacity: strength.band });
  page.drawText(lines[0]!, { x: 10, y: height - textSize - 5, size: textSize, font: bold, color: rgb(1, 1, 1) });
  page.drawText(lines[1]!, { x: 10, y: height - textSize * 2 - 9, size: textSize, font, color: rgb(1, 1, 1) });
  page.drawRectangle({ x: 0, y: 0, width, height: textSize + 10, color, opacity: strength.band });
  page.drawText(lines[1]!, { x: 10, y: 5, size: textSize, font, color: rgb(1, 1, 1) });
}

/** Watermarks every page, or draws nothing at all (no fonts added) when the owner turned it off. */
async function drawWatermarks(pdf: PDFDocument, info: WatermarkInfo) {
  if (!watermarkOn(info)) return;
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  for (const page of pdf.getPages()) watermarkPage(page, font, bold, info);
}

function drawStamps(page: PDFPage, bold: PDFFont, stamp: string, color: RGB, opacity: number) {
  const { width, height } = page.getSize();
  const angle = 30;
  const cos = Math.cos((angle * Math.PI) / 180);
  const sin = Math.sin((angle * Math.PI) / 180);
  // Size the stamp so the whole word fits across the page diagonally.
  const unitWidth = bold.widthOfTextAtSize(stamp, 1);
  const size = Math.max(14, Math.min(72, (width * 0.8) / (unitWidth * cos)));
  const dx = unitWidth * size * cos;
  const dy = unitWidth * size * sin;
  const x = (width - dx) / 2;
  // Evenly spaced stamps, every one fully on the page.
  const usable = Math.max(0, height - dy - size * 2);
  const count = Math.max(1, Math.min(4, Math.floor(usable / (dy + size * 2)) + 1));
  const step = count > 1 ? usable / (count - 1) : 0;
  const y0 = count > 1 ? size : (height - dy) / 2;
  for (let i = 0; i < count; i++) {
    page.drawText(stamp, { x, y: y0 + i * step, size, font: bold, color, opacity, rotate: degrees(angle) });
  }
}

function recipientLines(info: WatermarkInfo, when: string): [string, string] {
  const word = watermarkSafe((info.look ?? DEFAULT_WATERMARK).text, 'CONFIDENTIAL').toUpperCase();
  if (!info.download) {
    return [
      `${word} - Shared with: ${watermarkSafe(info.recipient, 'the named recipient')}`,
      `Viewed: ${when}  |  Link ${info.linkRef}  |  TrustPass – Authorized Viewing Only`,
    ];
  }
  const fallback = `the recipient of link ${info.linkRef}`;
  const by = info.download.downloadedBy ? ` (${watermarkSafe(info.download.downloadedBy, 'member')})` : '';
  return [
    `${word} - Downloaded for: ${watermarkSafe(info.recipient, fallback)}${by}`.slice(0, 160),
    `Downloaded: ${when}  |  Copy ${info.download.copyRef}  |  Link ${info.linkRef}  |  TrustPass`,
  ];
}

/**
 * Burns a watermark into every page. Images are wrapped in a single-page PDF
 * first, so recipients always get the same view-only, watermarked format.
 */
export async function watermarkDocument(data: Buffer, mimeType: string, info: WatermarkInfo): Promise<Buffer> {
  let pdf: PDFDocument;
  if (mimeType === 'application/pdf') {
    pdf = await PDFDocument.load(data, { updateMetadata: false });
  } else {
    pdf = await PDFDocument.create();
    const image = mimeType === 'image/png' ? await pdf.embedPng(data) : await pdf.embedJpg(data);
    const maxW = 1240;
    const scale = Math.min(1, maxW / image.width);
    const page = pdf.addPage([image.width * scale, image.height * scale]);
    page.drawImage(image, { x: 0, y: 0, width: image.width * scale, height: image.height * scale });
  }
  pdf.setTitle(watermarkOn(info) ? 'TrustPass - authorized viewing only' : 'TrustPass - shared document');
  pdf.setProducer('TrustPass');
  await drawWatermarks(pdf, info);
  return Buffer.from(await pdf.save());
}

/**
 * The recipient's downloadable copy: a NEW PDF, never the stored original.
 *  - pages are copied into a fresh document, so the original's metadata (author, XMP, outline,
 *    document-level actions) is not carried over; images are wrapped in a new page
 *  - every page gets the recipient's name, the download time, a per-download copy reference and
 *    the link reference, at the top and bottom, plus diagonal stamps
 *  - link annotations keep their appearance but lose any action
 * The input buffer is only read. The encrypted original in storage is never touched.
 */
export async function buildRecipientCopy(
  data: Buffer,
  mimeType: string,
  info: WatermarkInfo & { download: { copyRef: string; downloadedBy?: string } },
): Promise<Buffer> {
  const pdf = await PDFDocument.create({ updateMetadata: false });
  if (mimeType === 'application/pdf') {
    const source = await PDFDocument.load(data, { updateMetadata: false });
    const pages = await pdf.copyPages(source, source.getPageIndices());
    for (const page of pages) {
      page.node.delete(PDFName.of('AA'));
      const annots = page.node.Annots();
      if (annots) {
        for (let i = 0; i < annots.size(); i++) {
          const annot = annots.lookup(i);
          if (annot instanceof PDFDict) {
            annot.delete(PDFName.of('A'));
            annot.delete(PDFName.of('AA'));
          }
        }
      }
      pdf.addPage(page);
    }
  } else {
    const image = mimeType === 'image/png' ? await pdf.embedPng(data) : await pdf.embedJpg(data);
    const scale = Math.min(1, 1240 / image.width);
    const page = pdf.addPage([image.width * scale, image.height * scale]);
    page.drawImage(image, { x: 0, y: 0, width: image.width * scale, height: image.height * scale });
  }
  const now = info.viewedAt;
  pdf.setTitle(`TrustPass copy ${info.download.copyRef} - for the named recipient only`);
  pdf.setSubject(`Watermarked copy downloaded from TrustPass link ${info.linkRef}`);
  pdf.setKeywords(['trustpass', `trustpass-copy:${info.download.copyRef}`, `trustpass-link:${info.linkRef}`]);
  pdf.setProducer('TrustPass');
  pdf.setCreator('TrustPass');
  pdf.setAuthor('TrustPass');
  pdf.setCreationDate(now);
  pdf.setModificationDate(now);
  await drawWatermarks(pdf, info);
  return Buffer.from(await pdf.save());
}

/**
 * Stamps a freshly built PDF (e.g. a redacted copy made only of page images) for its recipient and
 * replaces its document info. View copies get the "Shared with" stamp; downloads (info.download)
 * get the per-download copy reference, exactly like buildRecipientCopy.
 */
export async function stampRecipientPdf(pdf: PDFDocument, info: WatermarkInfo, label = 'redacted copy'): Promise<Buffer> {
  const now = info.viewedAt;
  const ref = info.download?.copyRef;
  pdf.setTitle(ref ? `TrustPass ${label} ${ref} - for the named recipient only` : `TrustPass ${label} - authorized viewing only`);
  pdf.setSubject(`${label} shared through TrustPass link ${info.linkRef}`);
  pdf.setKeywords(['trustpass', `trustpass-link:${info.linkRef}`, ...(ref ? [`trustpass-copy:${ref}`] : [])]);
  pdf.setProducer('TrustPass');
  pdf.setCreator('TrustPass');
  pdf.setAuthor('TrustPass');
  pdf.setCreationDate(now);
  pdf.setModificationDate(now);
  await drawWatermarks(pdf, info);
  return Buffer.from(await pdf.save());
}


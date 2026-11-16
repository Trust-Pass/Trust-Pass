import { degrees, PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage } from 'pdf-lib';

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
}

function watermarkPage(page: PDFPage, font: PDFFont, bold: PDFFont, info: WatermarkInfo) {
  const { width, height } = page.getSize();
  const stamp = 'CONFIDENTIAL';
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
    page.drawText(stamp, { x, y: y0 + i * step, size, font: bold, color: NAVY, opacity: 0.09, rotate: degrees(angle) });
  }

  const when = `${info.viewedAt.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  const lines = [
    `CONFIDENTIAL - Shared with: ${watermarkSafe(info.recipient, 'the named recipient')}`,
    `Viewed: ${when}  |  Link ${info.linkRef}  |  TrustPass – Authorized Viewing Only`,
  ];
  const textSize = Math.max(6.5, Math.min(9, width / 70));
  const bandHeight = textSize * 2 + 14;
  page.drawRectangle({ x: 0, y: height - bandHeight, width, height: bandHeight, color: NAVY, opacity: 0.82 });
  page.drawText(lines[0]!, { x: 10, y: height - textSize - 5, size: textSize, font: bold, color: rgb(1, 1, 1) });
  page.drawText(lines[1]!, { x: 10, y: height - textSize * 2 - 9, size: textSize, font, color: rgb(1, 1, 1) });
  page.drawRectangle({ x: 0, y: 0, width, height: textSize + 10, color: NAVY, opacity: 0.82 });
  page.drawText(lines[1]!, { x: 10, y: 5, size: textSize, font, color: rgb(1, 1, 1) });
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
  pdf.setTitle('TrustPass - authorized viewing only');
  pdf.setProducer('TrustPass');
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  for (const page of pdf.getPages()) watermarkPage(page, font, bold, info);
  return Buffer.from(await pdf.save());
}

import { fileTypeFromBuffer } from 'file-type';
import { PDFDict, PDFDocument, PDFName, PDFStream } from 'pdf-lib';
import sharp from 'sharp';
import { AppError } from './errors';

export type AllowedMime = 'application/pdf' | 'image/png' | 'image/jpeg';

export interface ValidatedUpload {
  mimeType: AllowedMime;
  data: Buffer;
}

const reject = (message: string) => new AppError(415, 'unsupported_file', message);

// PDF features that can run code or carry hidden payloads.
const ACTIVE_PDF_KEYS = ['JavaScript', 'JS', 'Launch', 'EmbeddedFiles', 'EmbeddedFile', 'RichMedia', 'XFA', 'SubmitForm', 'ImportData'];

/**
 * Validates an uploaded file by its content, never by its name or the
 * browser-supplied type:
 *  - only PDF, PNG and JPEG are accepted (magic-byte detection)
 *  - images are decoded and re-encoded, which strips EXIF/GPS metadata and
 *    anything appended to the file (polyglots)
 *  - PDFs must parse, must not be encrypted and must not contain active
 *    content (JavaScript, launch actions, embedded files, forms that submit)
 */
export async function validateUpload(data: Buffer): Promise<ValidatedUpload> {
  if (data.length === 0) throw reject('The file is empty');

  const detected = await fileTypeFromBuffer(data);
  if (!detected) throw reject('This file type is not supported. Upload a PDF, PNG or JPEG file.');

  if (detected.mime === 'image/png' || detected.mime === 'image/jpeg') {
    return { mimeType: detected.mime, data: await reencodeImage(data, detected.mime) };
  }
  if (detected.mime === 'application/pdf') {
    await inspectPdf(data);
    return { mimeType: 'application/pdf', data };
  }
  throw reject(`Files of type ${detected.mime} are not accepted. Upload a PDF, PNG or JPEG file.`);
}

async function reencodeImage(data: Buffer, mime: 'image/png' | 'image/jpeg'): Promise<Buffer> {
  try {
    const image = sharp(data, { failOn: 'error', limitInputPixels: 40_000_000 }).rotate();
    const meta = await image.metadata();
    if (!meta.width || !meta.height) throw new Error('no dimensions');
    // sharp drops metadata (EXIF, GPS, XMP, ICC comments) unless asked to keep it.
    return mime === 'image/png'
      ? await image.png({ compressionLevel: 9 }).toBuffer()
      : await image.jpeg({ quality: 90, mozjpeg: true }).toBuffer();
  } catch {
    throw reject('The image could not be read. It may be damaged or not a real image.');
  }
}

async function inspectPdf(data: Buffer): Promise<void> {
  let pdf: PDFDocument;
  try {
    pdf = await PDFDocument.load(data, { updateMetadata: false, throwOnInvalidObject: true });
  } catch (err) {
    if (err instanceof Error && /encrypted/i.test(err.message)) {
      throw reject('Password-protected PDFs are not accepted. Remove the password and try again.');
    }
    throw reject('The PDF could not be read. It may be damaged.');
  }
  if (pdf.getPageCount() === 0) throw reject('The PDF has no pages');
  if (pdf.getPageCount() > 50) throw reject('PDFs are limited to 50 pages');

  // Walk every object, including those inside compressed object streams,
  // which pdf-lib has already decoded during load.
  for (const [, object] of pdf.context.enumerateIndirectObjects()) {
    const dict = object instanceof PDFDict ? object : object instanceof PDFStream ? object.dict : null;
    if (!dict) continue;
    for (const key of dict.keys()) {
      const name = key.decodeText();
      if (ACTIVE_PDF_KEYS.includes(name)) {
        throw reject('This PDF contains active content (scripts, embedded files or form actions), which is not allowed.');
      }
    }
    const action = dict.get(PDFName.of('S'));
    if (action instanceof PDFName && ['JavaScript', 'Launch', 'SubmitForm', 'ImportData'].includes(action.decodeText())) {
      throw reject('This PDF contains active content (scripts, embedded files or form actions), which is not allowed.');
    }
  }
}

/** Keep a display-safe file name: letters, digits, spaces and a few separators. */
export function sanitizeFilename(name: string | undefined): string {
  const base = (name ?? 'document').split(/[\\/]/).pop() ?? 'document';
  const cleaned = base.normalize('NFKC').replace(/[^\p{L}\p{N} ._()-]/gu, '').trim().slice(0, 100);
  return cleaned || 'document';
}

import { PDFDocument, PDFName, PDFString } from 'pdf-lib';
import sharp from 'sharp';
import { describe, expect, it } from 'vitest';
import { validateUpload } from '../../src/lib/upload-validation';
import { samplePdf, samplePng } from '../helpers';

async function pdfWithJavaScript() {
  const pdf = await PDFDocument.create();
  pdf.addPage([200, 200]);
  const action = pdf.context.obj({ Type: 'Action', S: 'JavaScript', JS: PDFString.of('app.alert("x")') });
  pdf.catalog.set(PDFName.of('OpenAction'), pdf.context.register(action));
  return Buffer.from(await pdf.save());
}

describe('upload validation', () => {
  it('accepts a real PDF unchanged', async () => {
    const pdf = await samplePdf();
    const result = await validateUpload(pdf);
    expect(result.mimeType).toBe('application/pdf');
    expect(result.data.equals(pdf)).toBe(true);
  });

  it('accepts PNG and JPEG and re-encodes them', async () => {
    const png = await samplePng();
    expect((await validateUpload(png)).mimeType).toBe('image/png');
    const jpeg = await sharp(png).jpeg().toBuffer();
    expect((await validateUpload(jpeg)).mimeType).toBe('image/jpeg');
  });

  it('strips EXIF/GPS metadata from photos', async () => {
    const png = await samplePng();
    const withExif = await sharp(png)
      .jpeg()
      .withExif({ IFD0: { Make: 'SecretPhoneMaker', ImageDescription: 'home address' } })
      .toBuffer();
    expect(withExif.includes(Buffer.from('SecretPhoneMaker'))).toBe(true);
    const cleaned = await validateUpload(withExif);
    expect(cleaned.data.includes(Buffer.from('SecretPhoneMaker'))).toBe(false);
  });

  it('removes data appended to an image (polyglot)', async () => {
    const png = await samplePng();
    const polyglot = Buffer.concat([png, Buffer.from('<html><script>alert(1)</script></html>')]);
    const result = await validateUpload(polyglot);
    expect(result.data.includes(Buffer.from('<script>'))).toBe(false);
  });

  it('rejects an executable renamed to .pdf', async () => {
    const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200, 0x90), Buffer.from('This program cannot be run in DOS mode')]);
    await expect(validateUpload(exe)).rejects.toMatchObject({ statusCode: 415 });
  });

  it('rejects HTML and SVG (script carriers)', async () => {
    await expect(validateUpload(Buffer.from('<!doctype html><script>alert(1)</script>'))).rejects.toMatchObject({ statusCode: 415 });
    await expect(
      validateUpload(Buffer.from('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>')),
    ).rejects.toMatchObject({ statusCode: 415 });
  });

  it('rejects other allowed-looking formats such as ZIP and GIF', async () => {
    const zip = Buffer.from('504b0304140000000800', 'hex');
    await expect(validateUpload(Buffer.concat([zip, Buffer.alloc(100)]))).rejects.toMatchObject({ statusCode: 415 });
    const gif = await sharp(await samplePng()).gif().toBuffer();
    await expect(validateUpload(gif)).rejects.toMatchObject({ statusCode: 415 });
  });

  it('rejects a PDF with JavaScript', async () => {
    await expect(validateUpload(await pdfWithJavaScript())).rejects.toThrow(/active content/);
  });

  it('rejects a truncated PDF', async () => {
    const pdf = await samplePdf();
    await expect(validateUpload(pdf.subarray(0, 60))).rejects.toMatchObject({ statusCode: 415 });
  });

  it('rejects empty files', async () => {
    await expect(validateUpload(Buffer.alloc(0))).rejects.toMatchObject({ statusCode: 415 });
  });
});

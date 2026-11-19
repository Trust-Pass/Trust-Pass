/**
 * QR decoding on the user's device. Pixels never leave the browser: only the decoded text is
 * sent to the API for the security check.
 *
 * Uses the browser's built-in BarcodeDetector when it supports QR codes (Chrome on Android,
 * Edge), otherwise jsQR in a Web Worker (/vendor/jsqr), so decoding never blocks the page.
 */

interface DetectedBarcode {
  rawValue: string;
}
interface BarcodeDetectorLike {
  detect(source: CanvasImageSource | ImageBitmap): Promise<DetectedBarcode[]>;
}
interface BarcodeDetectorCtor {
  new (options: { formats: string[] }): BarcodeDetectorLike;
  getSupportedFormats?: () => Promise<string[]>;
}

let nativePromise: Promise<BarcodeDetectorLike | null> | null = null;

function nativeDetector(): Promise<BarcodeDetectorLike | null> {
  nativePromise ??= (async () => {
    const Ctor = (globalThis as unknown as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector;
    if (!Ctor) return null;
    try {
      const formats = (await Ctor.getSupportedFormats?.()) ?? ['qr_code'];
      return formats.includes('qr_code') ? new Ctor({ formats: ['qr_code'] }) : null;
    } catch {
      return null;
    }
  })();
  return nativePromise;
}

// ---- jsQR worker -----------------------------------------------------------

let worker: Worker | null = null;
let nextId = 1;
const pending = new Map<number, (text: string | null) => void>();

function getWorker(): Worker {
  if (worker) return worker;
  const w = new Worker('/vendor/jsqr/qr-worker.js');
  w.onmessage = (event: MessageEvent<{ id: number; text: string | null }>) => {
    pending.get(event.data.id)?.(event.data.text);
    pending.delete(event.data.id);
  };
  w.onerror = () => {
    for (const resolve of pending.values()) resolve(null);
    pending.clear();
    worker?.terminate();
    worker = null;
  };
  worker = w;
  return w;
}

function decodeWithWorker(image: ImageData, thorough: boolean): Promise<string | null> {
  return new Promise((resolve) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
    }, 8000);
    pending.set(id, (text) => {
      clearTimeout(timer);
      resolve(text);
    });
    const buffer = image.data.buffer as ArrayBuffer;
    getWorker().postMessage({ id, width: image.width, height: image.height, data: buffer, thorough }, [buffer]);
  });
}

/** Stop the background decoder (when leaving the scanner page). */
export function releaseQrDecoder() {
  worker?.terminate();
  worker = null;
  for (const resolve of pending.values()) resolve(null);
  pending.clear();
}

// ---- Public API ------------------------------------------------------------

/**
 * Decode a QR code from what is currently drawn on a canvas.
 * fast: one quick attempt per camera frame. Otherwise (photos) try harder.
 */
export async function decodeCanvas(canvas: HTMLCanvasElement, options: { fast: boolean }): Promise<string | null> {
  const native = await nativeDetector();
  if (native) {
    try {
      const found = await native.detect(canvas);
      const value = found.find((b) => b.rawValue)?.rawValue;
      if (value) return value;
    } catch {
      /* fall back to jsQR */
    }
    if (options.fast) return null;
  }
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx || canvas.width === 0 || canvas.height === 0) return null;
  return decodeWithWorker(ctx.getImageData(0, 0, canvas.width, canvas.height), !options.fast);
}

/** Draw a video frame or image onto a canvas, scaled so its longest side is at most maxSide. */
export function drawScaled(source: CanvasImageSource, width: number, height: number, maxSide: number, canvas = document.createElement('canvas')) {
  const scale = Math.min(1, maxSide / Math.max(width, height));
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx?.drawImage(source, 0, 0, canvas.width, canvas.height);
  return canvas;
}

export const QR_IMAGE_MAX_BYTES = 15 * 1024 * 1024;

/** Decode a QR code from a photo or screenshot. Tries several sizes: jsQR works best around 500-1000 px. */
export async function decodeImageFile(file: File): Promise<string | null> {
  if (!file.type.startsWith('image/')) throw new Error('Choose an image file (PNG, JPEG, WebP or a screenshot).');
  if (file.size > QR_IMAGE_MAX_BYTES) throw new Error('That image is too large (15 MB at most).');
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new Error('This image could not be read. Try a PNG or JPEG.');
  }
  try {
    for (const side of [1000, 1600, 600]) {
      const canvas = drawScaled(bitmap, bitmap.width, bitmap.height, side);
      const text = await decodeCanvas(canvas, { fast: false });
      if (text) return text;
      if (Math.max(bitmap.width, bitmap.height) <= side) break;
    }
    return null;
  } finally {
    bitmap.close();
  }
}

export type CameraProblem = 'insecure' | 'unsupported' | 'denied' | 'not_found' | 'busy' | 'other';

export function cameraProblem(err: unknown): CameraProblem {
  const name = (err as { name?: string } | null)?.name ?? '';
  if (name === 'NotAllowedError' || name === 'SecurityError') return 'denied';
  if (name === 'NotFoundError' || name === 'OverconstrainedError') return 'not_found';
  if (name === 'NotReadableError' || name === 'AbortError') return 'busy';
  return 'other';
}

export const CAMERA_PROBLEM_TEXT: Record<CameraProblem, string> = {
  insecure: 'The camera only works on a secure (https) connection. Upload a photo of the code or paste the link instead.',
  unsupported: 'This browser cannot use the camera here. Upload a photo of the code or paste the link instead.',
  denied: 'Camera access was blocked. Allow the camera for this site in your browser settings, or upload a photo of the code instead.',
  not_found: 'No camera was found on this device. Upload a photo of the code or paste the link instead.',
  busy: 'The camera is being used by another app. Close it and try again.',
  other: 'The camera could not be started. Upload a photo of the code or paste the link instead.',
};

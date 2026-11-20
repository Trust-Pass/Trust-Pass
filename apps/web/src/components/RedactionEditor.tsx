import { Eye, EyeOff, Loader2, ScanSearch, Trash2, Undo2 } from 'lucide-react';
import clsx from 'clsx';
import { pdfjs } from '../lib/pdfjs';
import { forwardRef, useEffect, useImperativeHandle, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import { REDACTION_STYLE_LABELS, REDACTION_STYLES, SENSITIVE_KIND_LABELS, type Redaction, type RedactionStyle, type SensitiveKind } from '@trustpass/shared';
import { apiBlob, errorMessage } from '../lib/api';

/** Long edge of the page images sent for a redacted copy (the server allows up to 2400). */
const RENDER_EDGE = 1600;

export interface RedactionEditorHandle {
  /** PNG renderings of every page, in order (PDFs only; images are rendered on the server). */
  exportPages(): Promise<Blob[]>;
}

/** A run of text on a page, from the PDF's text layer, in page fractions (0..1). */
interface TextRun {
  str: string;
  /** Start of the run and the direction it advances in (whole run = origin + along). */
  origin: { x: number; y: number };
  along: { x: number; y: number };
  /** From the baseline up to the top of the glyphs. */
  up: { x: number; y: number };
  rtl: boolean;
}

interface PageView {
  canvas: HTMLCanvasElement;
  url: string;
  text: TextRun[];
  /** Pictures drawn on the page (photos, scanned signatures, logos), in page fractions. */
  pictures: Array<{ x: number; y: number; w: number; h: number }>;
}

/** Categories found in the text layer. Photos and signatures are found from the page drawing. */
type TextKind = Exclude<SensitiveKind, 'photo' | 'custom' | 'manual'>;
type Rule = { re: RegExp; group?: number; accept?: (m: string) => boolean; wholeRunAfter?: boolean };

const DIG = '0-9\u0660-\u0669';
const D = `[${DIG}]`;
const CURRENCY = '(?:SAR|SR|USD|EUR|GBP|AED|KWD|QAR|BHD|OMR|[$€£]|ريال|ر\\.س)';
const digitCount = (m: string) => m.replace(/[^0-9\u0660-\u0669]/g, '').length;
/** Card numbers pass the Luhn check; this keeps random long numbers out of "financial". */
const luhn = (m: string) => {
  const ds = m.replace(/\D/g, '');
  if (ds.length < 13 || ds.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < ds.length; i++) {
    let d = Number(ds[ds.length - 1 - i]);
    if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  }
  return sum % 10 === 0;
};

const PATTERNS: Record<TextKind, Rule[]> = {
  email: [{ re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g }],
  phone: [
    {
      re: new RegExp(`(?:\\+|00)?${D}[${DIG}\\s().-]{6,}${D}`, 'g'),
      // A phone number has a country prefix, a local mobile prefix (05…), or separators; a bare run
      // of digits is left to "ID numbers".
      accept: (m) => {
        const n = digitCount(m);
        if (n < 8 || n > 15 || luhn(m)) return false;
        const t = m.trim();
        return /^(?:\+|00)/.test(t) || /^(?:05|٠٥)[0-9\u0660-\u0669]{8}$/.test(t) || /[\s().-]/.test(t);
      },
    },
  ],
  id: [
    // Saudi national ID / iqama, and other long ID numbers.
    { re: new RegExp(`(?<![${DIG}])${D}{9,12}(?![${DIG}])`, 'g') },
    // The value after an ID label.
    { re: /(?:\bID\b|identity|national id|iqama|رقم الهوية|الهوية|الإقامة|السجل المدني)[^A-Za-z0-9\u0660-\u0669]{0,12}([A-Z0-9\u0660-\u0669-]{5,})/gi, group: 1 },
  ],
  passport: [
    { re: /(?:passport|جواز(?: السفر)?)[^A-Za-z0-9]{0,16}([A-Z0-9]{6,9})\b/gi, group: 1 },
    { re: /\b[A-Z]{1,2}[0-9]{6,8}\b/g },
  ],
  address: [
    // Everything after an address label on that line.
    { re: /(?:address|addr\.|العنوان|عنوان)\s*[:：-]?\s*(.+)$/gi, group: 1 },
    // Lines that look like a street address or P.O. box.
    {
      re: /.*\b(?:street|st\.|road|rd\.|avenue|ave\.|district|building|bldg|p\.?\s?o\.?\s?box|zip|postal code)\b.*|.*(?:شارع|حي |طريق|ص\.ب|الرمز البريدي|مبنى).*/gi,
    },
    // Saudi national short address, e.g. RRRD2929.
    { re: /\b[A-Z]{4}[0-9]{4}\b/g },
  ],
  financial: [
    { re: new RegExp(`${CURRENCY}\\s?${D}[${DIG},.]*`, 'gi') },
    { re: new RegExp(`${D}[${DIG},.]*\\s?${CURRENCY}`, 'gi') },
    { re: new RegExp(`\\b${D}{1,3}(?:,${D}{3})+(?:\\.${D}{1,2})?`, 'g') },
    // A number after a pay or account word, e.g. "Salary: 25000" or "الراتب ٢٥٠٠٠".
    {
      re: new RegExp(`(?:salary|wage|income|allowance|bonus|amount|total|balance|راتب|الراتب|بدل|مبلغ|الرصيد)[^${DIG}]{0,16}(${D}[${DIG},.]*)`, 'gi'),
      group: 1,
    },
    // IBAN and card numbers.
    { re: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b/g },
    { re: /\b(?:\d[ -]?){13,19}\b/g, accept: luhn },
  ],
  signature: [],
};
const SIGNATURE_LABEL = /(?:signature|signed by|sign here|التوقيع|توقيع)/i;

const escapeRegExp = (t: string) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Boxes (page fractions) covering every match in a page's text layer, padded generously. */
function findBoxes(page: number, runs: TextRun[], rules: Rule[], kind: SensitiveKind, style: RedactionStyle): Redaction[] {
  const out: Redaction[] = [];
  for (const run of runs) {
    const n = run.str.length;
    if (n === 0) continue;
    // Character ranges of every match in this run, merged so overlapping rules give one box.
    const ranges: Array<[number, number]> = [];
    for (const rule of rules) {
      for (const m of run.str.matchAll(rule.re)) {
        const text = rule.group ? m[rule.group] : m[0];
        if (!text || (rule.accept && !rule.accept(text))) continue;
        const start = (m.index ?? 0) + (rule.group ? m[0].indexOf(text) : 0);
        ranges.push([start, start + text.length]);
      }
    }
    ranges.sort((a, b) => a[0] - b[0]);
    const merged: Array<[number, number]> = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
      else merged.push([...r]);
    }
    for (const [start, stop] of merged) {
      // Glyph widths vary, so the box is widened by one character on each side.
      let f0 = Math.max(0, (start - 1) / n);
      let f1 = Math.min(1, (stop + 1) / n);
      if (run.rtl) [f0, f1] = [1 - f1, 1 - f0];
      const pts: Array<{ x: number; y: number }> = [];
      for (const f of [f0, f1]) {
        const bx = run.origin.x + run.along.x * f;
        const by = run.origin.y + run.along.y * f;
        // From a little below the baseline (descenders) to a little above the glyphs.
        pts.push({ x: bx - run.up.x * 0.3, y: by - run.up.y * 0.3 }, { x: bx + run.up.x * 1.15, y: by + run.up.y * 1.15 });
      }
      const x0 = Math.max(0, Math.min(...pts.map((p) => p.x)));
      const y0 = Math.max(0, Math.min(...pts.map((p) => p.y)));
      const x1 = Math.min(1, Math.max(...pts.map((p) => p.x)));
      const y1 = Math.min(1, Math.max(...pts.map((p) => p.y)));
      if (x1 - x0 > 0.001 && y1 - y0 > 0.001) out.push({ page, x: x0, y: y0, w: x1 - x0, h: y1 - y0, kind, style });
    }
  }
  return out;
}

/** Signature fields: the space after a "Signature" label on its line, and the band just above it. */
function signatureBoxes(page: number, runs: TextRun[], style: RedactionStyle): Redaction[] {
  const out: Redaction[] = [];
  for (const run of runs) {
    const m = SIGNATURE_LABEL.exec(run.str);
    if (!m || Math.abs(run.along.y) > 0.01) continue; // horizontal labels only
    // A field label ("Signature:", "التوقيع ____"), not the word inside a sentence.
    const after = run.str.slice(m.index + m[0].length);
    if (run.str.trim().length > 40 || !/^[\s:：._\-–—]*$/.test(after)) continue;
    const n = run.str.length;
    const labelEnd = run.origin.x + run.along.x * ((m.index + m[0].length) / n);
    const height = Math.abs(run.up.y);
    const baseline = run.origin.y;
    const x = Math.min(0.97, labelEnd + 0.005);
    const y = Math.max(0, baseline - height * 3.2);
    const w = Math.max(0.01, 0.97 - x);
    const h = Math.min(1 - y, height * 4.2);
    if (w > 0.02) out.push({ page, x, y, w, h, kind: 'signature', style });
  }
  return out;
}

/** All automatic findings of one page, by category. */
function detectPage(page: number, view: PageView, style: RedactionStyle): Redaction[] {
  const out: Redaction[] = [];
  for (const kind of Object.keys(PATTERNS) as TextKind[]) {
    if (kind === 'signature') continue;
    out.push(...findBoxes(page, view.text, PATTERNS[kind], kind, style));
  }
  out.push(...signatureBoxes(page, view.text, style));
  for (const p of view.pictures) out.push({ page, ...p, kind: 'photo', style });
  return out;
}

/** How each style looks while editing (the shared copy is drawn by the server). */
const STYLE_SWATCH: Record<RedactionStyle, string> = {
  black: 'bg-black',
  white: 'bg-white ring-1 ring-inset ring-slate-400',
  pixelate: 'bg-[conic-gradient(#8a8f99_25%,#c9ccd2_0_50%,#8a8f99_0_75%,#c9ccd2_0)] bg-[length:10px_10px]',
  blur: 'bg-slate-200/90 backdrop-blur-md',
};

const sameBox = (a: Redaction, b: Redaction) =>
  a.page === b.page && Math.abs(a.x - b.x) < 0.002 && Math.abs(a.y - b.y) < 0.002 && Math.abs(a.w - b.w) < 0.002 && Math.abs(a.h - b.h) < 0.002;

/**
 * Lets the owner mark areas to hide. Pages are rendered here with pdf.js; the boxes are sent as
 * fractions of each page and burned into the pixels by the server, so nothing under a box can be
 * recovered from the recipient's copy.
 */
export const RedactionEditor = forwardRef<RedactionEditorHandle, {
  /** The stored document to load, or `file` for a file not uploaded yet (chosen at upload). */
  documentId?: string;
  file?: Blob;
  mimeType: string;
  boxes: Redaction[];
  onChange: (boxes: Redaction[]) => void;
}>(function RedactionEditor({ documentId, file, mimeType, boxes, onChange }, ref) {
  const [pages, setPages] = useState<PageView[]>([]);
  const [state, setState] = useState<{ status: 'loading' | 'ready' | 'error'; message?: string }>({ status: 'loading' });
  const [draft, setDraft] = useState<(Redaction & { x0: number; y0: number }) | null>(null);
  // The drag in progress lives in a ref, so a fast drag never reads a stale render.
  const drag = useRef<(Redaction & { x0: number; y0: number }) | null>(null);
  const pagesRef = useRef<PageView[]>([]);
  const [custom, setCustom] = useState('');
  const [found, setFound] = useState<string | null>(null);
  const [style, setStyle] = useState<RedactionStyle>(boxes[0]?.style ?? 'black');
  /** Everything detected, by category, so a category can be shown again and hidden again. */
  const [detected, setDetected] = useState<Partial<Record<SensitiveKind, Redaction[]>> | null>(null);
  const hasText = pages.some((p) => p.text.length > 0);
  const hasPictures = pages.some((p) => p.pictures.length > 0);
  const canDetect = hasText || hasPictures;

  const detect = () => {
    const all = pages.flatMap((p, i) => detectPage(i, p, style));
    const byKind: Partial<Record<SensitiveKind, Redaction[]>> = {};
    for (const b of all) (byKind[b.kind] ??= []).push(b);
    setDetected(byKind);
    // Detected items start hidden: the owner then chooses what recipients may see.
    const fresh = all.filter((m, i) => !boxes.some((b) => sameBox(b, m)) && !all.slice(0, i).some((o) => sameBox(o, m)));
    if (fresh.length) onChange([...boxes, ...fresh]);
    setFound(
      all.length === 0
        ? 'Nothing sensitive was found automatically. Mark anything else by hand.'
        : `Found ${all.length} item${all.length === 1 ? '' : 's'}. All are hidden: choose below what recipients may see.`,
    );
  };
  const kindHidden = (kind: SensitiveKind) => boxes.some((b) => b.kind === kind);
  const toggleKind = (kind: SensitiveKind) => {
    if (kindHidden(kind)) onChange(boxes.filter((b) => b.kind !== kind));
    else onChange([...boxes, ...(detected?.[kind] ?? []).map((b) => ({ ...b, style }))]);
  };
  const changeStyle = (next: RedactionStyle) => {
    setStyle(next);
    // One style for the whole copy: every hidden area takes it.
    if (boxes.length) onChange(boxes.map((b) => ({ ...b, style: next })));
  };
  const hideCustom = () => {
    const text = custom.trim();
    if (text.length < 2) return;
    const matches = pages.flatMap((p, i) => findBoxes(i, p.text, [{ re: new RegExp(escapeRegExp(text), 'gi') }], 'custom', style));
    const fresh = matches.filter((m, i) => !boxes.some((b) => sameBox(b, m)) && !matches.slice(0, i).some((o) => sameBox(o, m)));
    if (fresh.length) onChange([...boxes, ...fresh]);
    setFound(
      matches.length === 0
        ? `No "${text}" found in the document's text. Mark it by hand.`
        : `${fresh.length === 0 ? 'Already hidden' : `Hid ${fresh.length}`}: "${text}". Check them on the pages below.`,
    );
  };

  useImperativeHandle(ref, () => ({
    exportPages: async () => {
      if (mimeType !== 'application/pdf') return [];
      // JPEG keeps a page around 0.2–0.6 MB. The server burns the boxes into these pixels and
      // re-encodes the result, so no compression artefact can carry hidden content.
      return Promise.all(
        pagesRef.current.map(
          (p) => new Promise<Blob>((resolve, reject) => p.canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Could not prepare a page'))), 'image/jpeg', 0.92)),
        ),
      );
    },
  }));

  useEffect(() => {
    let cancelled = false;
    let task: pdfjs.PDFDocumentLoadingTask | null = null;
    const made: string[] = [];
    (async () => {
      try {
        const blob = file ?? (await apiBlob(`/api/documents/${documentId}/file`));
        const rendered: PageView[] = [];
        if (mimeType === 'application/pdf') {
          task = pdfjs.getDocument({ data: new Uint8Array(await blob.arrayBuffer()), enableXfa: false, disableAutoFetch: true });
          const pdf = await task.promise;
          for (let n = 1; n <= pdf.numPages; n++) {
            const page = await pdf.getPage(n);
            const base = page.getViewport({ scale: 1 });
            const viewport = page.getViewport({ scale: RENDER_EDGE / Math.max(base.width, base.height) });
            const canvas = document.createElement('canvas');
            canvas.width = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            await page.render({ canvas, viewport, background: '#ffffff' }).promise;
            if (cancelled) return;
            // The text layer, positioned on the rendered page, for "find and hide".
            const text: TextRun[] = [];
            const content = await page.getTextContent();
            const W = viewport.width;
            const H = viewport.height;
            const toPage = (x: number, y: number) => {
              const [vx, vy] = viewport.convertToViewportPoint(x, y);
              return { x: vx! / W, y: vy! / H };
            };
            for (const item of content.items) {
              if (!('str' in item) || !item.str.trim()) continue;
              const [a, b, c, d, e, f] = item.transform as number[];
              const size = Math.hypot(c!, d!) || Math.hypot(a!, b!);
              const len = Math.hypot(a!, b!) || 1;
              const ux = a! / len;
              const uy = b! / len;
              const origin = toPage(e!, f!);
              const end = toPage(e! + ux * item.width, f! + uy * item.width);
              const top = toPage(e! - uy * size, f! + ux * size);
              text.push({
                str: item.str,
                origin,
                along: { x: end.x - origin.x, y: end.y - origin.y },
                up: { x: top.x - origin.x, y: top.y - origin.y },
                rtl: item.dir === 'rtl',
              });
            }
            // Pictures: follow the drawing operations to where each image lands on the page.
            const pictures: PageView['pictures'] = [];
            const ops = await page.getOperatorList();
            let ctm = [1, 0, 0, 1, 0, 0];
            const stack: number[][] = [];
            const IMAGE_OPS = new Set([pdfjs.OPS.paintImageXObject, pdfjs.OPS.paintInlineImageXObject, pdfjs.OPS.paintImageMaskXObject, pdfjs.OPS.paintImageXObjectRepeat]);
            for (let k = 0; k < ops.fnArray.length; k++) {
              const fn = ops.fnArray[k];
              const args = ops.argsArray[k] as unknown[];
              if (fn === pdfjs.OPS.save) stack.push(ctm);
              else if (fn === pdfjs.OPS.restore) ctm = stack.pop() ?? ctm;
              else if (fn === pdfjs.OPS.transform) ctm = pdfjs.Util.transform(ctm, args as number[]);
              else if (fn === pdfjs.OPS.paintFormXObjectBegin) {
                stack.push(ctm);
                if (Array.isArray(args?.[0])) ctm = pdfjs.Util.transform(ctm, args[0] as number[]);
              } else if (fn === pdfjs.OPS.paintFormXObjectEnd) ctm = stack.pop() ?? ctm;
              else if (IMAGE_OPS.has(fn!)) {
                const corners = [
                  [0, 0],
                  [1, 0],
                  [0, 1],
                  [1, 1],
                ].map(([u, v]) => toPage(ctm[0]! * u! + ctm[2]! * v! + ctm[4]!, ctm[1]! * u! + ctm[3]! * v! + ctm[5]!));
                const x0 = Math.max(0, Math.min(...corners.map((c) => c.x)));
                const y0 = Math.max(0, Math.min(...corners.map((c) => c.y)));
                const x1 = Math.min(1, Math.max(...corners.map((c) => c.x)));
                const y1 = Math.min(1, Math.max(...corners.map((c) => c.y)));
                const area = (x1 - x0) * (y1 - y0);
                // Skip specks and full-page images (a scan is one big picture: hiding it hides everything).
                if (area > 0.002 && area < 0.8) pictures.push({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
              }
            }
            const url = URL.createObjectURL(await new Promise<Blob>((r) => canvas.toBlob((b) => r(b!), 'image/png')));
            made.push(url);
            rendered.push({ canvas, url, text, pictures });
          }
        } else {
          const bitmap = await createImageBitmap(blob);
          const canvas = document.createElement('canvas');
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
          canvas.getContext('2d')!.drawImage(bitmap, 0, 0);
          const url = URL.createObjectURL(blob);
          made.push(url);
          rendered.push({ canvas, url, text: [], pictures: [] });
        }
        if (cancelled) return;
        pagesRef.current = rendered;
        setPages(rendered);
        setState({ status: 'ready' });
      } catch (err) {
        if (!cancelled) setState({ status: 'error', message: errorMessage(err) });
      }
    })();
    return () => {
      cancelled = true;
      void task?.destroy();
      for (const u of made) URL.revokeObjectURL(u);
    };
  }, [documentId, file, mimeType]);

  const point = (e: ReactPointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    return { x: Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)), y: Math.min(1, Math.max(0, (e.clientY - r.top) / r.height)) };
  };
  const start = (page: number) => (e: ReactPointerEvent<HTMLDivElement>) => {
    e.currentTarget.setPointerCapture?.(e.pointerId);
    const p = point(e);
    drag.current = { page, x: p.x, y: p.y, w: 0, h: 0, x0: p.x, y0: p.y, kind: 'manual', style };
    setDraft(drag.current);
  };
  const move = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    const p = point(e);
    drag.current = { ...d, x: Math.min(p.x, d.x0), y: Math.min(p.y, d.y0), w: Math.abs(p.x - d.x0), h: Math.abs(p.y - d.y0) };
    setDraft(drag.current);
  };
  const end = (e: ReactPointerEvent<HTMLDivElement>) => {
    move(e);
    const d = drag.current;
    drag.current = null;
    setDraft(null);
    if (d && d.w > 0.005 && d.h > 0.005) {
      onChange([...boxes, { page: d.page, x: d.x, y: d.y, w: Math.min(d.w, 1 - d.x), h: Math.min(d.h, 1 - d.y), kind: 'manual', style }]);
    }
  };

  if (state.status === 'loading') {
    return (
      <p className="flex items-center gap-2 py-6 text-sm text-slate-500">
        <Loader2 className="size-4 animate-spin" /> Preparing the pages…
      </p>
    );
  }
  if (state.status === 'error') return <p className="py-4 text-sm text-red-400">The pages could not be prepared: {state.message}</p>;

  return (
    <div className="space-y-3" data-testid="redaction-editor">
      <div className="rounded-xl bg-slate-50 p-3 ring-1 ring-slate-200" data-testid="find-and-hide">
        <p className="mb-2 flex items-center gap-1.5 text-sm font-medium text-ink">
          <ScanSearch className="size-4" /> Sensitive information
        </p>
        {canDetect ? (
          <>
            <button
              type="button"
              onClick={detect}
              className="inline-flex h-9 items-center gap-1.5 rounded-xl bg-accent/10 px-3 text-sm font-medium text-ink ring-1 ring-inset ring-accent-line hover:bg-accent/20"
            >
              <ScanSearch className="size-4" /> {detected ? 'Detect again' : 'Detect sensitive information'}
            </button>
            {detected && Object.keys(detected).length > 0 && (
              <ul className="mt-3 divide-y divide-slate-200 rounded-xl ring-1 ring-slate-200" data-testid="sensitive-kinds">
                {(Object.keys(detected) as SensitiveKind[]).map((kind) => {
                  const hidden = kindHidden(kind);
                  return (
                    <li key={kind} className="flex items-center justify-between gap-2 px-3 py-2 text-sm">
                      <span className="text-ink">
                        {SENSITIVE_KIND_LABELS[kind]} <span className="text-slate-500">({detected[kind]!.length})</span>
                      </span>
                      <button
                        type="button"
                        aria-pressed={hidden}
                        aria-label={`${SENSITIVE_KIND_LABELS[kind]}: ${hidden ? 'hidden' : 'visible'}`}
                        onClick={() => toggleKind(kind)}
                        className={clsx(
                          'inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg px-2.5 text-[13px] font-medium ring-1 ring-inset',
                          hidden ? 'bg-ink/90 text-surface ring-transparent' : 'text-slate-600 ring-slate-300 hover:bg-accent/10',
                        )}
                      >
                        {hidden ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                        {hidden ? 'Hidden' : 'Visible'}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
            {/* Not a <form>: the editor sits inside other forms, and forms cannot nest. */}
            {hasText && (
              <div className="mt-3 flex gap-2">
                <input
                  value={custom}
                  onChange={(e) => setCustom(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key !== 'Enter') return;
                    e.preventDefault();
                    hideCustom();
                  }}
                  placeholder="Other text, e.g. a name"
                  aria-label="Text to hide"
                  className="h-9 min-w-0 flex-1 rounded-xl bg-surface px-3 text-sm text-ink ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-accent"
                />
                <button
                  type="button"
                  onClick={hideCustom}
                  disabled={custom.trim().length < 2}
                  className="inline-flex h-9 shrink-0 items-center rounded-xl px-3 text-sm font-medium text-ink ring-1 ring-inset ring-slate-300 hover:bg-accent/10 disabled:opacity-40"
                >
                  Hide
                </button>
              </div>
            )}
            {found && (
              <p className="mt-2 text-[13px] text-slate-600" role="status" data-testid="find-result">
                {found}
              </p>
            )}
            <p className="mt-2 text-[12px] text-slate-500">
              Detection runs in your browser on the document's text and pictures: IDs, passport and phone numbers, emails, addresses,
              financial details, photos and signature fields. It can miss things, so check the pages and the preview.
            </p>
          </>
        ) : (
          <p className="text-[13px] text-slate-500">
            {mimeType === 'application/pdf'
              ? 'This PDF has no text layer (it is probably a scan), so nothing can be detected automatically. Drag over each area to hide it.'
              : 'Pictures have no text layer, so nothing can be detected automatically. Drag over each area to hide it.'}
          </p>
        )}
        <div className="mt-3">
          <p className="mb-1.5 text-[13px] font-medium text-slate-600">Hiding style</p>
          <div role="radiogroup" aria-label="Hiding style" className="flex flex-wrap gap-2">
            {REDACTION_STYLES.map((st) => (
              <button
                key={st}
                type="button"
                role="radio"
                aria-checked={style === st}
                onClick={() => changeStyle(st)}
                className={clsx(
                  'inline-flex h-9 items-center gap-2 rounded-xl px-3 text-sm ring-1 ring-inset',
                  style === st ? 'bg-accent-soft text-ink ring-accent-line' : 'text-slate-600 ring-slate-300 hover:bg-accent/10',
                )}
              >
                <span className={clsx('size-4 rounded-[4px]', STYLE_SWATCH[st])} aria-hidden />
                {REDACTION_STYLE_LABELS[st]}
              </button>
            ))}
          </div>
          <p className="mt-1.5 text-[12px] text-slate-500">Every style replaces what is underneath in the shared copy: pixelate and blur are drawn fresh, not from your document.</p>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 text-[13px] text-slate-600">
        <span>Drag over anything the recipient must not see. {boxes.length} area{boxes.length === 1 ? '' : 's'} hidden.</span>
        <span className="flex gap-2">
          <button type="button" className="inline-flex items-center gap-1 rounded-lg px-2 py-1 ring-1 ring-slate-300 disabled:opacity-40" disabled={boxes.length === 0} onClick={() => onChange(boxes.slice(0, -1))}>
            <Undo2 className="size-3.5" /> Undo
          </button>
          <button type="button" className="inline-flex items-center gap-1 rounded-lg px-2 py-1 ring-1 ring-slate-300 disabled:opacity-40" disabled={boxes.length === 0} onClick={() => onChange([])}>
            <Trash2 className="size-3.5" /> Clear
          </button>
        </span>
      </div>
      {pages.map((p, i) => (
        <div key={p.url}>
          {pages.length > 1 && <p className="mb-1 text-xs text-slate-500">Page {i + 1}</p>}
          <div
            className="relative cursor-crosshair touch-none select-none overflow-hidden rounded-lg ring-1 ring-slate-300"
            data-testid={`redaction-page-${i}`}
            onPointerDown={start(i)}
            onPointerMove={move}
            onPointerUp={end}
            onPointerCancel={() => {
              drag.current = null;
              setDraft(null);
            }}
          >
            <img src={p.url} alt={`Page ${i + 1}`} className="block w-full" draggable={false} />
            {boxes.map((b, j) =>
              b.page === i ? (
                <button
                  key={j}
                  type="button"
                  title="Remove this hidden area"
                  aria-label={`Remove hidden area ${j + 1}`}
                  onPointerDown={(e) => e.stopPropagation()}
                  onClick={() => onChange(boxes.filter((_, k) => k !== j))}
                  className={clsx('absolute', STYLE_SWATCH[b.style ?? 'black'])}
                  style={{ left: `${b.x * 100}%`, top: `${b.y * 100}%`, width: `${b.w * 100}%`, height: `${b.h * 100}%` }}
                />
              ) : null,
            )}
            {draft && draft.page === i && (
              <div className="pointer-events-none absolute bg-black/70 ring-2 ring-accent" style={{ left: `${draft.x * 100}%`, top: `${draft.y * 100}%`, width: `${draft.w * 100}%`, height: `${draft.h * 100}%` }} />
            )}
          </div>
        </div>
      ))}
      <p className="text-[13px] text-slate-500">Tap a hidden area to show it again.</p>
    </div>
  );
});

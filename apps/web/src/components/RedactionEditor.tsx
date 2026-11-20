import { Loader2, ScanSearch, Trash2, Undo2 } from 'lucide-react';
import * as pdfjs from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { forwardRef, useEffect, useImperativeHandle, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react';
import type { Redaction } from '@trustpass/shared';
import { apiBlob, errorMessage } from '../lib/api';

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

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
}

export type FindKind = 'email' | 'phone' | 'amount' | 'id';

export const FIND_LABELS: Record<FindKind, string> = {
  email: 'Email addresses',
  phone: 'Phone numbers',
  amount: 'Amounts and salaries',
  id: 'ID and account numbers',
};

const D = '[0-9\u0660-\u0669]';
const CURRENCY = '(?:SAR|SR|USD|EUR|GBP|AED|KWD|QAR|BHD|OMR|[$€£]|ريال|ر\\.س)';
const PATTERNS: Record<FindKind, Array<{ re: RegExp; group?: number; accept?: (m: string) => boolean }>> = {
  email: [{ re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g }],
  phone: [
    {
      re: new RegExp(`(?:\\+|00)?${D}[${'0-9\u0660-\u0669'}\\s().-]{6,}${D}`, 'g'),
      accept: (m) => {
        const digits = m.replace(/[^0-9\u0660-\u0669]/g, '').length;
        return digits >= 8 && digits <= 15;
      },
    },
  ],
  amount: [
    { re: new RegExp(`${CURRENCY}\\s?${D}[${'0-9\u0660-\u0669'},.]*`, 'gi') },
    { re: new RegExp(`${D}[${'0-9\u0660-\u0669'},.]*\\s?${CURRENCY}`, 'gi') },
    { re: new RegExp(`\\b${D}{1,3}(?:,${D}{3})+(?:\\.${D}{1,2})?`, 'g') },
    // A number after a pay word, e.g. "Salary: 25000" or "الراتب ٢٥٠٠٠".
    { re: new RegExp(`(?:salary|wage|income|allowance|bonus|amount|total|راتب|الراتب|بدل|مبلغ)[^0-9\u0660-\u0669]{0,16}(${D}[${'0-9\u0660-\u0669'},.]*)`, 'gi'), group: 1 },
  ],
  id: [
    { re: new RegExp(`(?<![0-9\u0660-\u0669])${D}{9,}(?![0-9\u0660-\u0669])`, 'g') },
    { re: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b/g },
  ],
};

const escapeRegExp = (t: string) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Boxes (page fractions) covering every match in a page's text layer, padded generously. */
function findBoxes(page: number, runs: TextRun[], kind: FindKind | { text: string }): Redaction[] {
  const rules = typeof kind === 'string' ? PATTERNS[kind] : [{ re: new RegExp(escapeRegExp(kind.text.trim()), 'gi') }];
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
      if (x1 - x0 > 0.001 && y1 - y0 > 0.001) out.push({ page, x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
    }
  }
  return out;
}

const sameBox = (a: Redaction, b: Redaction) =>
  a.page === b.page && Math.abs(a.x - b.x) < 0.002 && Math.abs(a.y - b.y) < 0.002 && Math.abs(a.w - b.w) < 0.002 && Math.abs(a.h - b.h) < 0.002;

/**
 * Lets the owner mark areas to hide. Pages are rendered here with pdf.js; the boxes are sent as
 * fractions of each page and burned into the pixels by the server, so nothing under a box can be
 * recovered from the recipient's copy.
 */
export const RedactionEditor = forwardRef<RedactionEditorHandle, {
  documentId: string;
  mimeType: string;
  boxes: Redaction[];
  onChange: (boxes: Redaction[]) => void;
}>(function RedactionEditor({ documentId, mimeType, boxes, onChange }, ref) {
  const [pages, setPages] = useState<PageView[]>([]);
  const [state, setState] = useState<{ status: 'loading' | 'ready' | 'error'; message?: string }>({ status: 'loading' });
  const [draft, setDraft] = useState<(Redaction & { x0: number; y0: number }) | null>(null);
  // The drag in progress lives in a ref, so a fast drag never reads a stale render.
  const drag = useRef<(Redaction & { x0: number; y0: number }) | null>(null);
  const pagesRef = useRef<PageView[]>([]);
  const [custom, setCustom] = useState('');
  const [found, setFound] = useState<string | null>(null);
  const hasText = pages.some((p) => p.text.length > 0);

  const findAndHide = (kind: FindKind | { text: string }, what: string) => {
    const matches = pages.flatMap((p, i) => findBoxes(i, p.text, kind));
    const fresh = matches.filter((m, i) => !boxes.some((b) => sameBox(b, m)) && !matches.slice(0, i).some((o) => sameBox(o, m)));
    if (fresh.length) onChange([...boxes, ...fresh]);
    setFound(
      matches.length === 0
        ? `No ${what} found in the document's text. Mark anything else by hand.`
        : `${fresh.length === 0 ? 'Already hidden' : `Hid ${fresh.length}`}: ${what}. Check them on the pages below.`,
    );
  };
  const hideCustom = () => {
    if (custom.trim().length >= 2) findAndHide({ text: custom }, `"${custom.trim()}"`);
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
        const blob = await apiBlob(`/api/documents/${documentId}/file`);
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
            const url = URL.createObjectURL(await new Promise<Blob>((r) => canvas.toBlob((b) => r(b!), 'image/png')));
            made.push(url);
            rendered.push({ canvas, url, text });
          }
        } else {
          const bitmap = await createImageBitmap(blob);
          const canvas = document.createElement('canvas');
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
          canvas.getContext('2d')!.drawImage(bitmap, 0, 0);
          const url = URL.createObjectURL(blob);
          made.push(url);
          rendered.push({ canvas, url, text: [] });
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
  }, [documentId, mimeType]);

  const point = (e: ReactPointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    return { x: Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)), y: Math.min(1, Math.max(0, (e.clientY - r.top) / r.height)) };
  };
  const start = (page: number) => (e: ReactPointerEvent<HTMLDivElement>) => {
    e.currentTarget.setPointerCapture?.(e.pointerId);
    const p = point(e);
    drag.current = { page, x: p.x, y: p.y, w: 0, h: 0, x0: p.x, y0: p.y };
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
      onChange([...boxes, { page: d.page, x: d.x, y: d.y, w: Math.min(d.w, 1 - d.x), h: Math.min(d.h, 1 - d.y) }]);
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
          <ScanSearch className="size-4" /> Find and hide
        </p>
        {hasText ? (
          <>
            <div className="flex flex-wrap gap-2">
              {(Object.keys(FIND_LABELS) as FindKind[]).map((k) => (
                <button
                  key={k}
                  type="button"
                  onClick={() => findAndHide(k, FIND_LABELS[k].toLowerCase())}
                  className="inline-flex h-9 items-center rounded-xl px-3 text-sm text-ink ring-1 ring-inset ring-slate-300 hover:bg-accent/10"
                >
                  {FIND_LABELS[k]}
                </button>
              ))}
            </div>
            {/* Not a <form>: the editor sits inside the share form, and forms cannot nest. */}
            <div className="mt-2 flex gap-2">
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
            {found && (
              <p className="mt-2 text-[13px] text-slate-600" role="status" data-testid="find-result">
                {found}
              </p>
            )}
            <p className="mt-2 text-[12px] text-slate-500">
              Searches the document's text layer in your browser. Scanned pages and pictures have no text: mark those by hand, and always check the preview.
            </p>
          </>
        ) : (
          <p className="text-[13px] text-slate-500">
            {mimeType === 'application/pdf'
              ? 'This PDF has no text layer (it is probably a scan), so nothing can be found automatically. Drag over each area to hide it.'
              : 'Pictures have no text layer, so nothing can be found automatically. Drag over each area to hide it.'}
          </p>
        )}
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
                  className="absolute bg-black"
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
      <p className="text-[13px] text-slate-500">Tap a black area to remove it.</p>
    </div>
  );
});

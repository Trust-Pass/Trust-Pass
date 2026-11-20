import { Loader2, Trash2, Undo2 } from 'lucide-react';
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

interface PageView {
  canvas: HTMLCanvasElement;
  url: string;
}

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
            const url = URL.createObjectURL(await new Promise<Blob>((r) => canvas.toBlob((b) => r(b!), 'image/png')));
            made.push(url);
            rendered.push({ canvas, url });
          }
        } else {
          const bitmap = await createImageBitmap(blob);
          const canvas = document.createElement('canvas');
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
          canvas.getContext('2d')!.drawImage(bitmap, 0, 0);
          const url = URL.createObjectURL(blob);
          made.push(url);
          rendered.push({ canvas, url });
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

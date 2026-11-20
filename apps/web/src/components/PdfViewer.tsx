import { FileWarning, Loader2 } from 'lucide-react';
import * as pdfjs from 'pdfjs-dist';
import workerUrl from 'pdfjs-dist/build/pdf.worker.min.mjs?url';
import { useEffect, useRef, useState } from 'react';
import { apiBlob, errorMessage } from '../lib/api';

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

/**
 * Renders a PDF to canvases (no download button, no text layer). This is a
 * deterrent only: the watermark burned in on the server is what identifies a
 * leaked copy.
 */
export function PdfViewer({ src, label }: { src: string; label: string }) {
  const container = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<{ status: 'loading' | 'ready' | 'error'; message?: string; pages?: number }>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    let task: pdfjs.PDFDocumentLoadingTask | null = null;
    const host = container.current;
    if (!host) return;
    host.innerHTML = '';

    (async () => {
      try {
        const blob = await apiBlob(src);
        const data = new Uint8Array(await blob.arrayBuffer());
        task = pdfjs.getDocument({ data, enableXfa: false, disableAutoFetch: true });
        const pdf = await task.promise;
        if (cancelled) return;
        const width = Math.min(host.clientWidth || 600, 900);
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        for (let n = 1; n <= pdf.numPages; n++) {
          const page = await pdf.getPage(n);
          if (cancelled) return;
          const base = page.getViewport({ scale: 1 });
          const viewport = page.getViewport({ scale: (width / base.width) * ratio });
          const canvas = document.createElement('canvas');
          canvas.width = Math.floor(viewport.width);
          canvas.height = Math.floor(viewport.height);
          canvas.style.width = `${Math.floor(viewport.width / ratio)}px`;
          canvas.style.maxWidth = '100%';
          canvas.style.height = 'auto';
          canvas.className = 'pdf-page mx-auto block rounded-lg bg-white shadow-card ring-1 ring-slate-200';
          canvas.setAttribute('role', 'img');
          canvas.setAttribute('aria-label', `${label}, page ${n} of ${pdf.numPages}`);
          canvas.addEventListener('contextmenu', (e) => e.preventDefault());
          host.appendChild(canvas);
          await page.render({ canvas, viewport }).promise;
        }
        if (!cancelled) setState({ status: 'ready', pages: pdf.numPages });
      } catch (err) {
        if (!cancelled) setState({ status: 'error', message: errorMessage(err) });
      }
    })();

    return () => {
      cancelled = true;
      void task?.destroy();
    };
  }, [src, label]);

  return (
    <div>
      {state.status === 'loading' && (
        <div className="flex items-center justify-center gap-2 py-16 text-sm text-slate-500">
          <Loader2 className="size-5 animate-spin text-teal-400" /> Decrypting and rendering…
        </div>
      )}
      {state.status === 'error' && (
        <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-red-700">
          <FileWarning className="size-6" />
          {state.message}
        </div>
      )}
      <div ref={container} className="space-y-3" />
    </div>
  );
}

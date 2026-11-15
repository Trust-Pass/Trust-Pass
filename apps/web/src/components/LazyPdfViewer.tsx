import { lazy, Suspense } from 'react';
import { Spinner } from './ui';

// pdf.js is large; load it only when a document is actually shown.
const PdfViewer = lazy(() => import('./PdfViewer').then((m) => ({ default: m.PdfViewer })));

export function LazyPdfViewer(props: { src: string; label: string }) {
  return (
    <Suspense fallback={<Spinner label="Loading viewer" />}>
      <PdfViewer {...props} />
    </Suspense>
  );
}

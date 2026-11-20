/**
 * The one place the app loads pdf.js.
 *
 * pdfjs-dist's modern build (pdfjs-dist/build) assumes the newest JavaScript, for example
 * Map.prototype.getOrInsertComputed, in both the page and its worker. iPhone Safari does not have
 * it yet, so pages failed with "this.#n.getOrInsertComputed is not a function". The legacy build
 * ships the same library with polyfills for those features, for the page and the worker alike,
 * so it runs on iOS Safari as well as desktop browsers. Import pdf.js only from here.
 */
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import workerUrl from 'pdfjs-dist/legacy/build/pdf.worker.min.mjs?url';

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

export { pdfjs };

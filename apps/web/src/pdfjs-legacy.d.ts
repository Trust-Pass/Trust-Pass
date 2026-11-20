// The legacy build exposes the same API as the modern one; reuse its types.
declare module 'pdfjs-dist/legacy/build/pdf.mjs' {
  export * from 'pdfjs-dist';
}

# jsQR 1.4.0 (vendored)

QR code decoder used by the QR Security Scanner when the browser has no built-in
`BarcodeDetector` (iPhone Safari, Firefox, desktop browsers).

- Source: https://github.com/cozmo/jsQR, `dist/jsQR.js`, commit 8e6a036beafa7053dd44b1b76ac578d22b1b3311
- License: Apache License 2.0 (see `LICENSE` in this folder)
- SHA-256 of `jsQR.js`: 3325b0888fa4745c4e6940897d8c4f426fbaae76901fcbfe1871a04e90a51655
- Unmodified. It contains no `eval` or `new Function`, so it runs under the site's strict CSP.
- Vendored instead of installed from npm so the decoder ships as a static file loaded only
  inside a Web Worker (`qr-worker.js`), off the main thread and only on the scanner page.

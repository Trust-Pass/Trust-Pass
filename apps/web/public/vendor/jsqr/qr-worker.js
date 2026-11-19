/* QR decoding off the main thread. Receives raw RGBA pixels, returns the decoded text or null.
 * The image never leaves the device: there is no network access in here. */
/* global jsQR */
importScripts('/vendor/jsqr/jsQR.js');

self.onmessage = function (event) {
  var msg = event.data || {};
  var text = null;
  try {
    var result = jsQR(new Uint8ClampedArray(msg.data), msg.width, msg.height, {
      inversionAttempts: msg.thorough ? 'attemptBoth' : 'dontInvert',
    });
    text = result && typeof result.data === 'string' ? result.data : null;
  } catch (e) {
    text = null;
  }
  self.postMessage({ id: msg.id, text: text });
};

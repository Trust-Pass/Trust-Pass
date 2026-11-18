# QR Shield: QR Security Scanner

Checks a QR code, or a pasted link, **before** it is opened, and explains in plain language what it does and why it may be dangerous.

Page: **QR Scanner** (`/app/scan`), for signed-in users. API: `POST /api/qr/check`.

## The experience (live camera first)

1. Opening the page **starts the camera** (the browser asks for permission the first time).
2. The user points the camera at a QR code.
3. Frames are decoded continuously (about 6 per second); the first QR code found is read automatically. No upload or paste needed.
4. The camera stops and the content is analysed at once; the result appears on the same page (scrolled into view on phones).
5. The result shows the verdict (**Safe / Suspicious / Dangerous**), a **safety score** in percent (100 − risk), the **destination** URL (or the content for non-web codes) and every finding explained.
6. Nothing is ever opened automatically. "Open link" (Safe), "Open anyway" with confirmation (Suspicious), never for Dangerous.
7. **Scan another QR code** restarts the camera in one tap. The code just read is ignored for 2.5 seconds so it is not re-read instantly.

If the camera is unavailable (permission refused, no camera, not https, in use by another app), the page says why and offers **Try the camera again**; **Image** and **Paste a link** remain as alternatives.

## How it works

| Step | Where | Notes |
| --- | --- | --- |
| 1. Read the code | The user's device | Camera (live), a photo or screenshot, or pasted text. Decoded by the browser's built-in `BarcodeDetector` when it supports QR codes, otherwise by jsQR 1.4.0 (vendored, Apache-2.0) in a Web Worker. **Images and camera frames never leave the device.** |
| 2. Analyse | Server, `analyzeQrContent()` in `packages/shared/src/qr-shield.ts` | Offline rules only. The address is **never opened, fetched or resolved** (no tracking of the person checking, no SSRF). |
| 3. TrustPass links | Server | If the content is a share link on the official TrustPass address, the server says whether it is active, expired, revoked or does not exist. It does not count a view and reveals nothing about the document or its owner. |
| 4. Show | Web | Verdict, risk score, what the code contains (as plain text, never as a clickable link), the real site, and each finding. |

## Verdicts

Safety score = 100 − risk score. Risk adds up the findings (low 10, medium 25, high 55, critical 90; at most 100).

- **Dangerous** (`danger`): any high or critical finding, or three medium ones. "Open" is not offered.
- **Suspicious** (`caution`): any medium finding, or two low ones. "Open anyway" asks for confirmation first.
- **Safe** (`safe`): no warning signs found. This is not a guarantee, and the page says so.

## What is checked

| Content | Checks |
| --- | --- |
| Web links | Imitation of known names (banks, government services, delivery companies, social networks, the university, **TrustPass itself**), including letter swaps (`paypa1`, `g00gle`, one letter added or removed); text before `@`; raw or private IP addresses (also decimal and hex forms); international look-alike letters (punycode); hidden direction-reversing characters; `http` instead of `https`; unusual ports; free hosting platforms; link shorteners; risky domain endings (`.zip`, `.xyz`, …); addresses that carry a second address (open redirects); downloads of apps or programs (`.apk`, `.exe`, `.mobileconfig`, …); heavy encoding; very long or deep addresses; sign-in, payment or "verify" wording |
| Code, not a page | `javascript:`, `data:`, `file:`, `vbscript:`, `blob:` → always dangerous |
| Other QR types | Wi-Fi (open or WEP networks; the password is never echoed), SMS, phone, email, map location, contact card, calendar event, authenticator setup (`otpauth:`), cryptocurrency payments, Android `intent:` links, iPhone `itms-services:` installs, other app links |
| Text | Plain text is safe; a link inside the text is analysed too |

## Privacy and logging

- The content is not stored. A **dangerous** result is logged as a security event (`qr_threat_detected`, shown in the Activity log) with only the source (camera, image, paste), the kind and the finding ids.
- Rate limit: 60 checks per minute per user. Content is limited to 4096 characters.
- `Permissions-Policy` now allows the camera for TrustPass's own pages only (`camera=(self)`); microphone, location and payment stay off.

## Tests

- `apps/api/test/unit/qr-shield.test.ts`: the analyzer on safe, caution and dangerous examples of every content type.
- `apps/api/test/integration/qr.test.ts`: sign-in required, input limits, no content stored, TrustPass link status (active, expired, revoked, fake) without counting a view, camera permission header.
- `e2e/tests/qr-camera.spec.ts`: the **complete camera-to-analysis flow** with Chromium's fake camera playing a QR video (`e2e/fixtures/qr-http-shortlink.y4m`): the camera starts with no click, the code is read and analysed, the result shows *Suspicious*, a 50% safety score, the destination and the explanations; nothing is opened, the camera is released; **Scan another QR code** restarts the camera and reads again. Also: "Open anyway" asks first and opens only after confirming.
- `e2e/tests/qr-camera-danger.spec.ts`: a phishing QR code through the camera (`qr-phishing.y4m`) is *Dangerous*, 0% safety, explained, cannot be opened, and is logged in the Activity log without the address.
- `e2e/tests/qr-scanner.spec.ts`: no usable camera (clear message, other options still work), pasted phishing link and script, a clean link, a QR photo decoded in the browser, an image without a code and a broken image.

## Limits

- No reputation lookups (Google Safe Browsing, VirusTotal, …): they would send the user's links to a third party. Could be added later as an opt-in.
- Short links are flagged, not expanded: expanding would mean visiting them.
- The brand list is fixed in code and covers well-known and Saudi names; it will never be complete.

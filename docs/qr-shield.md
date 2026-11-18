# QR Shield: QR Security Scanner

Checks a QR code, or a pasted link, **before** it is opened, and explains in plain language what it does and why it may be dangerous.

Page: **QR Scanner** (`/app/scan`), for signed-in users. API: `POST /api/qr/check`.

## How it works

| Step | Where | Notes |
| --- | --- | --- |
| 1. Read the code | The user's device | Camera (live), a photo or screenshot, or pasted text. Decoded by the browser's built-in `BarcodeDetector` when it supports QR codes, otherwise by jsQR 1.4.0 (vendored, Apache-2.0) in a Web Worker. **Images and camera frames never leave the device.** |
| 2. Analyse | Server, `analyzeQrContent()` in `packages/shared/src/qr-shield.ts` | Offline rules only. The address is **never opened, fetched or resolved** (no tracking of the person checking, no SSRF). |
| 3. TrustPass links | Server | If the content is a share link on the official TrustPass address, the server says whether it is active, expired, revoked or does not exist. It does not count a view and reveals nothing about the document or its owner. |
| 4. Show | Web | Verdict, risk score, what the code contains (as plain text, never as a clickable link), the real site, and each finding. |

## Verdicts

- **Dangerous**: any high or critical finding, or three medium ones. "Open" is not offered.
- **Be careful**: any medium finding, or two low ones. "Open anyway" asks for confirmation first.
- **No warning signs found**: nothing suspicious. This is not a guarantee, and the page says so.

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
- `e2e/tests/qr-scanner.spec.ts`: pasted phishing link and script, a clean link, a QR photo decoded in the browser, an image without a code, and **live camera scanning** using Chromium's fake camera fed with `e2e/fixtures/qr-http-shortlink.y4m`; the camera is checked to be released afterwards.

## Limits

- No reputation lookups (Google Safe Browsing, VirusTotal, …): they would send the user's links to a third party. Could be added later as an opt-in.
- Short links are flagged, not expanded: expanding would mean visiting them.
- The brand list is fixed in code and covers well-known and Saudi names; it will never be complete.

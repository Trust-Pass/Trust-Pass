# Test fixtures

- `qr-http-shortlink.png`: a photo of a QR code containing `http://goo.by/wkEtco`, taken from the
  jsQR test suite (https://github.com/cozmo/jsQR, `tests/end-to-end/10/input.png`, Apache License 2.0).
- `qr-http-shortlink.y4m`: the same photo on a white 640x480 frame, as a raw video file. Chromium plays
  it as a fake camera (`--use-file-for-fake-video-capture`) to test live camera scanning.
- `no-qr.png`: a plain drawing with no QR code (made for these tests).
- `qr-phishing.png` / `qr-phishing.y4m`: a QR code for `https://www.paypal.com@paypa1-secure.xyz/login` (a fake, never-registered
  phishing-style address), made with segno (https://github.com/heuer/segno, BSD license) and turned into a fake-camera
  video with `make-camera-video.py`.

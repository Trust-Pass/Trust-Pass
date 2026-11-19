"""Turn a QR code image into a raw .y4m video that Chromium plays as a fake camera.

Usage: python3 make-camera-video.py input.png output.y4m
Needs Pillow. The image is centred on a white 640x480 frame, like a phone pointed at a code.
"""
import sys
from PIL import Image

W, H = 640, 480
src = Image.open(sys.argv[1]).convert('RGB')
canvas = Image.new('RGB', (W, H), (255, 255, 255))
scale = min(W * 0.8 / src.width, H * 0.8 / src.height)
img = src.resize((int(src.width * scale), int(src.height * scale)), Image.LANCZOS)
canvas.paste(img, ((W - img.width) // 2, (H - img.height) // 2))
y, cb, cr = canvas.convert('YCbCr').split()
cb, cr = cb.resize((W // 2, H // 2)), cr.resize((W // 2, H // 2))
with open(sys.argv[2], 'wb') as f:
    f.write(f'YUV4MPEG2 W{W} H{H} F5:1 Ip A1:1 C420jpeg\n'.encode())
    for _ in range(2):
        f.write(b'FRAME\n' + y.tobytes() + cb.tobytes() + cr.tobytes())

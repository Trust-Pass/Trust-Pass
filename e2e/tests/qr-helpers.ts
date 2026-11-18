import type { Page } from '@playwright/test';

interface Watched {
  __streams: MediaStream[];
  __popups: string[];
}

/** Record every camera stream the page opens and every attempt to open a new window. */
export async function watchCameraAndPopups(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as Watched;
    w.__streams = [];
    w.__popups = [];
    const original = navigator.mediaDevices?.getUserMedia?.bind(navigator.mediaDevices);
    if (original) {
      navigator.mediaDevices.getUserMedia = async (c) => {
        const s = await original(c);
        w.__streams.push(s);
        return s;
      };
    }
    window.open = (url?: string | URL) => {
      w.__popups.push(String(url));
      return null;
    };
  });
}

/** Streams opened, camera tracks still live, and windows the page tried to open. */
export function cameraStats(page: Page) {
  return page.evaluate(() => {
    const w = window as unknown as Watched;
    return {
      opened: w.__streams.length,
      live: w.__streams.flatMap((s) => s.getTracks()).filter((t) => t.readyState === 'live').length,
      popups: w.__popups,
    };
  });
}

/**
 * Reduce a User-Agent string to a coarse "Browser on OS" label. Only this
 * label is stored, never the full string, to limit fingerprinting data.
 */
export function userAgentFamily(ua: string | undefined): string {
  if (!ua) return 'Unknown client';
  const s = ua.slice(0, 512);

  let os = 'Unknown OS';
  if (/iPhone|iPad|iPod/.test(s)) os = 'iOS';
  else if (/Android/.test(s)) os = 'Android';
  else if (/Windows/.test(s)) os = 'Windows';
  else if (/Mac OS X|Macintosh/.test(s)) os = 'macOS';
  else if (/CrOS/.test(s)) os = 'ChromeOS';
  else if (/Linux/.test(s)) os = 'Linux';

  let browser = 'Other browser';
  if (/curl|wget|python|httpie|postman|go-http|java\//i.test(s)) browser = 'Script or tool';
  else if (/Edg\//.test(s)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(s)) browser = 'Opera';
  else if (/SamsungBrowser/.test(s)) browser = 'Samsung Internet';
  else if (/Firefox\/|FxiOS/.test(s)) browser = 'Firefox';
  else if (/Chrome\/|CriOS/.test(s)) browser = 'Chrome';
  else if (/Safari\//.test(s)) browser = 'Safari';

  return `${browser} on ${os}`;
}

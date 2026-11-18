/**
 * QR Shield: offline risk analysis for the content of a QR code or a pasted link.
 *
 * Pure function, no network: it never opens, fetches or resolves the address, so a malicious
 * link cannot track or attack the person checking it (and the server cannot be used for SSRF).
 * The verdict is a warning system, not a guarantee: "safe" means "no warning signs found".
 */

// The shared package compiles without DOM or Node types; the WHATWG URL class exists at runtime
// in browsers and Node. This module-scoped declaration only describes the parts used here.
interface WhatwgUrl {
  protocol: string;
  username: string;
  password: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  href: string;
  searchParams: { forEach(cb: (value: string, key: string) => void): void };
}
declare const URL: { new (input: string): WhatwgUrl };

export const QR_CONTENT_MAX_LENGTH = 4096;

export type QrVerdict = 'safe' | 'caution' | 'danger';
export type QrSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type QrContentKind =
  | 'trustpass_link'
  | 'web_link'
  | 'script'
  | 'app_link'
  | 'wifi'
  | 'email'
  | 'phone'
  | 'sms'
  | 'location'
  | 'contact'
  | 'calendar'
  | 'authenticator'
  | 'payment'
  | 'text';

export interface QrFinding {
  id: string;
  severity: QrSeverity;
  title: string;
  detail: string;
}

export interface QrUrlParts {
  scheme: string;
  host: string;
  /** The part of the host that identifies who controls the site (e.g. example.com.sa). */
  registrableDomain: string;
  port: string | null;
  path: string;
  isOfficial: boolean;
}

export interface QrAnalysis {
  kind: QrContentKind;
  verdict: QrVerdict;
  /** 0 (no signs) to 100 (certainly dangerous). */
  riskScore: number;
  summary: string;
  /** What the code contains, exactly as decoded (for display as plain text only). */
  content: string;
  url: QrUrlParts | null;
  /** Share-link token when the content is an official TrustPass share link. */
  trustpassToken: string | null;
  findings: QrFinding[];
  /** True only for http(s) links that are not dangerous. The UI must still confirm on caution. */
  canOpen: boolean;
}

export interface QrAnalyzeOptions {
  /** Origin of this TrustPass deployment, e.g. https://trustpass-gwnp.onrender.com */
  appOrigin: string;
}

// ---------------------------------------------------------------------------
// Reference data
// ---------------------------------------------------------------------------

/** Public suffixes with two labels that this analyzer must know to find the registrable domain. */
const MULTI_LABEL_SUFFIXES = new Set([
  'com.sa', 'edu.sa', 'gov.sa', 'net.sa', 'org.sa', 'med.sa', 'sch.sa', 'pub.sa',
  'co.ae', 'gov.ae', 'ac.ae', 'com.bh', 'com.kw', 'gov.kw', 'com.qa', 'gov.qa', 'com.om', 'gov.om',
  'com.eg', 'gov.eg', 'edu.eg', 'com.jo', 'gov.jo', 'com.tr', 'gov.tr',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.cn', 'com.hk', 'com.sg', 'com.my', 'co.id', 'co.in',
  'com.br', 'com.mx', 'com.ar', 'co.za',
]);

/** Hosting platforms where every subdomain belongs to a different, unverified owner. */
const SHARED_HOSTING = new Set([
  'onrender.com', 'github.io', 'vercel.app', 'netlify.app', 'herokuapp.com', 'pages.dev', 'workers.dev',
  'web.app', 'firebaseapp.com', 'blogspot.com', 'azurewebsites.net', 'glitch.me', 'repl.co', 'replit.app',
  'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'wixsite.com', 'weebly.com', 'square.site',
  'webflow.io', 'framer.website', 'godaddysites.com', 'surge.sh', 'fly.dev', 'railway.app',
  '000webhostapp.com', 'sites.google.com', 'forms.gle', 'appspot.com', 'r2.dev', 'ipfs.io',
]);

/** Link shorteners: the real destination is hidden until the link is opened. */
const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'ow.ly', 'buff.ly', 'cutt.ly',
  'rebrand.ly', 'rb.gy', 'tiny.cc', 'shorturl.at', 's.id', 't.ly', 'lnkd.in', 'qrco.de', 'bl.ink', 'short.io',
  'shorte.st', 'adf.ly', 'tiny.one', 'urlz.fr', 'clck.ru', 'u.to', 'trib.al', 'han.gl', 'linktr.ee', 'qr.io',
  'me-qr.com', 'qrcodes.pro', 'l.ead.me', 'surl.li', 'urlr.me', 'bit.do', 'goo.by',
]);

/** Domain endings that are cheap, rarely used by real organizations and common in scams. */
const RISKY_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link', 'country', 'kim',
  'rest', 'fit', 'loan', 'men', 'racing', 'review', 'download', 'stream', 'gdn', 'cam', 'icu', 'monster',
  'buzz', 'lat', 'sbs', 'cfd', 'quest', 'bond', 'mom', 'support', 'live', 'cyou', 'beauty', 'hair',
]);

/** Well-known names that scammers imitate, with the domains that really belong to them. */
const BRANDS: Array<{ name: string; label: string; domains: string[] }> = [
  { name: 'Google', label: 'google', domains: ['google.com', 'google.com.sa', 'goo.gl', 'youtube.com', 'gmail.com'] },
  { name: 'Apple', label: 'apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', label: 'microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com'] },
  { name: 'Outlook', label: 'outlook', domains: ['outlook.com', 'live.com', 'office.com'] },
  { name: 'PayPal', label: 'paypal', domains: ['paypal.com', 'paypal.me'] },
  { name: 'Amazon', label: 'amazon', domains: ['amazon.com', 'amazon.sa', 'amazon.ae', 'amazon.co.uk'] },
  { name: 'Netflix', label: 'netflix', domains: ['netflix.com'] },
  { name: 'Facebook', label: 'facebook', domains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'Instagram', label: 'instagram', domains: ['instagram.com'] },
  { name: 'WhatsApp', label: 'whatsapp', domains: ['whatsapp.com', 'wa.me'] },
  { name: 'Snapchat', label: 'snapchat', domains: ['snapchat.com'] },
  { name: 'TikTok', label: 'tiktok', domains: ['tiktok.com'] },
  { name: 'LinkedIn', label: 'linkedin', domains: ['linkedin.com', 'lnkd.in'] },
  { name: 'Absher', label: 'absher', domains: ['absher.sa'] },
  { name: 'Nafath', label: 'nafath', domains: ['iam.gov.sa', 'nafath.sa'] },
  { name: 'Tawakkalna', label: 'tawakkalna', domains: ['ta.sdaia.gov.sa', 'sdaia.gov.sa'] },
  { name: 'Al Rajhi Bank', label: 'alrajhi', domains: ['alrajhibank.com.sa'] },
  { name: 'SNB AlAhli', label: 'alahli', domains: ['alahli.com', 'snb.com'] },
  { name: 'Riyad Bank', label: 'riyadbank', domains: ['riyadbank.com'] },
  { name: 'STC', label: 'stcpay', domains: ['stcpay.com.sa', 'stc.com.sa'] },
  { name: 'Saudi Post', label: 'splonline', domains: ['splonline.com.sa', 'spl.com.sa'] },
  { name: 'Aramex', label: 'aramex', domains: ['aramex.com'] },
  { name: 'DHL', label: 'dhl', domains: ['dhl.com'] },
  { name: 'SMSA', label: 'smsa', domains: ['smsaexpress.com'] },
  { name: 'Imam University', label: 'imamu', domains: ['imamu.edu.sa'] },
  { name: 'Tuwaiq Academy', label: 'tuwaiq', domains: ['tuwaiq.edu.sa'] },
];

const SENSITIVE_WORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'account', 'update', 'secure', 'security',
  'password', 'passwd', 'wallet', 'bank', 'payment', 'pay', 'invoice', 'billing', 'otp', 'kyc', 'reset',
  'confirm', 'unlock', 'suspend', 'suspended', 'refund', 'prize', 'gift', 'reward', 'claim', 'delivery', 'parcel',
];

const DOWNLOAD_EXTENSIONS = /\.(apk|aab|xapk|exe|msi|scr|bat|cmd|com|pif|js|jse|vbs|vbe|wsf|hta|jar|ps1|psm1|dmg|pkg|ipa|iso|img|lnk|reg|cpl|msix|appx|mobileconfig)$/i;
const REDIRECT_PARAMS = new Set(['url', 'u', 'redirect', 'redirect_uri', 'redirect_url', 'redir', 'next', 'target', 'dest', 'destination', 'return', 'returnurl', 'return_to', 'continue', 'goto', 'link', 'out', 'to', 'r']);
const APP_SCHEMES = new Set(['whatsapp', 'tg', 'market', 'itms-apps', 'fb', 'twitter', 'instagram', 'snapchat', 'spotify', 'zoommtg', 'msteams', 'skype', 'viber', 'upi', 'maps', 'comgooglemaps', 'facetime', 'slack', 'discord']);
const SCRIPT_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:', 'chrome:', 'jar:']);
const SHARE_PATH = /^\/s\/([A-Za-z0-9_-]{20,100})\/?$/;
// Characters that change text direction or are invisible: used to disguise names (e.g. "gpj.exe").
// Written as escapes so this file itself contains no invisible characters.
const BIDI_OR_INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/;
const SEVERITY_POINTS: Record<QrSeverity, number> = { info: 0, low: 10, medium: 25, high: 55, critical: 90 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function registrableDomain(host: string): string {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  const lastThree = labels.slice(-3).join('.');
  if (SHARED_HOSTING.has(lastTwo) || MULTI_LABEL_SUFFIXES.has(lastTwo)) return lastThree;
  if (SHARED_HOSTING.has(lastThree) && labels.length >= 4) return labels.slice(-4).join('.');
  return lastTwo;
}

function sharedHostingBase(host: string): string | null {
  const labels = host.split('.');
  for (const n of [3, 2]) {
    if (labels.length > n) {
      const base = labels.slice(-n).join('.');
      if (SHARED_HOSTING.has(base)) return base;
    }
  }
  return null;
}

function isIpv4(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPrivateAddress(host: string): boolean {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host.startsWith('[')) {
    const h = host.slice(1, -1).toLowerCase();
    return h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80') || h.startsWith('::ffff:');
  }
  if (!isIpv4(host)) return false;
  const [a, b] = host.split('.').map(Number) as [number, number];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

/** Undo the character swaps scammers use to fake a name (paypa1 → paypal, g00gle → google). */
function deconfuse(label: string): string {
  return label
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[0]/g, 'o')
    .replace(/[1!|]/g, 'l')
    .replace(/[3]/g, 'e')
    .replace(/[4@]/g, 'a')
    .replace(/[5$]/g, 's')
    .replace(/[7]/g, 't')
    .replace(/[8]/g, 'b')
    .replace(/[9]/g, 'g');
}

function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j]!;
      prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length]!;
}

function hostBelongsTo(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

function truncate(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function parseKeyValues(body: string, separator = ';'): Record<string, string> {
  // WIFI:T:WPA;S:My\;Net;P:pass;; - backslash escapes ; , : and \
  const out: Record<string, string> = {};
  let key = '';
  let value = '';
  let inKey = true;
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === '\\' && i + 1 < body.length) {
      (inKey ? (key += body[i + 1]) : (value += body[i + 1]));
      i++;
    } else if (inKey && c === ':') {
      inKey = false;
    } else if (c === separator) {
      if (key) out[key.toUpperCase()] = value;
      key = '';
      value = '';
      inKey = true;
    } else if (inKey) {
      key += c;
    } else {
      value += c;
    }
  }
  if (key) out[key.toUpperCase()] = value;
  return out;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

function verdictFor(findings: QrFinding[]): { verdict: QrVerdict; riskScore: number } {
  const points = findings.reduce((sum, f) => sum + SEVERITY_POINTS[f.severity], 0);
  const riskScore = Math.min(100, points);
  const hasSevere = findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  const mediums = findings.filter((f) => f.severity === 'medium').length;
  const lows = findings.filter((f) => f.severity === 'low').length;
  if (hasSevere || mediums >= 3) return { verdict: 'danger', riskScore: Math.max(riskScore, 60) };
  if (mediums > 0 || lows >= 2) return { verdict: 'caution', riskScore: Math.max(riskScore, 20) };
  return { verdict: 'safe', riskScore };
}

function analyzeWebUrl(raw: string, url: WhatwgUrl, app: WhatwgUrl, findings: QrFinding[], addedScheme: boolean) {
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const appHost = app.hostname.toLowerCase();
  const isOfficial = host === appHost && url.port === app.port && url.protocol === app.protocol;
  const reg = registrableDomain(host);
  const labels = host.split('.');
  const tld = labels[labels.length - 1] ?? '';
  const path = `${url.pathname}${url.search}${url.hash}`;

  if (addedScheme) {
    findings.push({ id: 'no_scheme', severity: 'info', title: 'No http:// or https:// at the start', detail: 'Phones usually open this as a web address, so it was checked as one.' });
  }
  if (url.protocol === 'http:' && !isOfficial) {
    findings.push({ id: 'not_https', severity: 'medium', title: 'Not encrypted (http, not https)', detail: 'Anyone on the same network can read or change what you send to this site. Never enter passwords or card details here.' });
  }
  if (url.username || url.password) {
    findings.push({ id: 'userinfo', severity: 'high', title: 'Disguised address (text before "@")', detail: `Everything before "@" is ignored by the browser. The real site is ${host}, not what the start of the link suggests.` });
  }
  if (isIpv4(host) || host.startsWith('[')) {
    findings.push(
      isPrivateAddress(host)
        ? { id: 'private_ip', severity: 'high', title: 'Points to a device on a local network', detail: 'The link targets a private network address (a router, camera or another computer), which a public QR code should never do.' }
        : { id: 'ip_address', severity: 'high', title: 'Uses a raw IP address instead of a name', detail: 'Real organizations use a domain name. Hiding behind a number is a common phishing trick.' },
    );
  } else if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    findings.push({ id: 'private_ip', severity: 'high', title: 'Points to a device on a local network', detail: 'The link targets this device or the local network, which a public QR code should never do.' });
  }
  if (labels.some((l) => l.startsWith('xn--'))) {
    findings.push({ id: 'punycode', severity: 'high', title: 'International letters that can imitate another site', detail: `The name contains non-Latin letters (shown as ${truncate(host)}). They can look identical to a real site's name, for example a Cyrillic "а" in "аpple.com".` });
  }
  if (BIDI_OR_INVISIBLE.test(raw)) {
    findings.push({ id: 'hidden_chars', severity: 'high', title: 'Hidden or direction-reversing characters', detail: 'The text contains invisible characters that can make a name look different from what it is.' });
  }
  if (url.port && !isOfficial) {
    findings.push({ id: 'unusual_port', severity: 'medium', title: `Unusual port (${url.port})`, detail: 'Normal websites do not need a port number. Test servers and malicious sites often do.' });
  }

  // Imitating a known name.
  if (!isOfficial) {
    const brandList = [...BRANDS, { name: 'TrustPass', label: 'trustpass', domains: [appHost] }];
    const ownLabels = labels.slice(0, -1); // ignore the TLD
    let flagged = false;
    for (const brand of brandList) {
      if (brand.domains.some((d) => hostBelongsTo(host, d))) continue;
      const hit = ownLabels.some((label) => {
        const plain = label.toLowerCase();
        const clean = deconfuse(plain);
        const parts = clean.split('-');
        if (parts.includes(brand.label) || clean === brand.label) return true;
        if (brand.label === 'trustpass' && (clean.includes('trustpass') || clean.includes('trust-pass'))) return true;
        // One letter changed, added or removed (paypall, gooogle). Short names are skipped: too many real words are one letter away.
        if (brand.label.length >= 6 && parts.some((p) => p.length >= 5 && editDistance(p, brand.label) === 1)) return true;
        return brand.label.length >= 5 && plain !== clean && clean.includes(brand.label);
      });
      if (hit) {
        flagged = true;
        findings.push({
          id: brand.label === 'trustpass' ? 'trustpass_lookalike' : 'brand_lookalike',
          severity: 'high',
          title: `Imitates ${brand.name}`,
          detail: `The address uses the name "${brand.name}" but the site is ${reg}, which does not belong to ${brand.name}. Real ${brand.name} addresses end in ${brand.domains.slice(0, 2).join(' or ')}.`,
        });
        break;
      }
    }
    if (!flagged) {
      const words = `${host} ${path}`.toLowerCase();
      const matched = SENSITIVE_WORDS.filter((w) => new RegExp(`(^|[^a-z])${w.replace('-', '\\-')}([^a-z]|$)`).test(words));
      if (matched.length > 0) {
        findings.push({ id: 'sensitive_words', severity: 'low', title: 'Asks you to sign in, pay or verify', detail: `It contains words such as "${matched.slice(0, 3).join('", "')}". Only continue if you expected this request from ${reg}.` });
      }
    }
  }

  const hosting = sharedHostingBase(host);
  if (hosting && !isOfficial) {
    findings.push({ id: 'shared_hosting', severity: 'medium', title: `Free hosting service (${hosting})`, detail: `Anyone can create a site on ${hosting} in minutes. The name before it was chosen by whoever made the site.` });
  }
  if (SHORTENERS.has(host) || SHORTENERS.has(reg)) {
    findings.push({ id: 'shortener', severity: 'medium', title: 'Short link hides the real destination', detail: `${reg} forwards you to another address that cannot be seen until you open it.` });
  }
  if (RISKY_TLDS.has(tld)) {
    findings.push({
      id: 'risky_tld',
      severity: 'medium',
      title: `Domain ending ".${tld}" is often used in scams`,
      detail: tld === 'zip' || tld === 'mov' ? `".${tld}" looks like a file name but is a website.` : 'These endings are cheap and rarely used by banks, governments or universities.',
    });
  }
  if (labels.length >= 5 || host.length > 60) {
    findings.push({ id: 'long_host', severity: 'low', title: 'Unusually long or deep address', detail: 'Long chains of names are used to push the real domain out of view on a phone screen.' });
  }
  if (DOWNLOAD_EXTENSIONS.test(url.pathname)) {
    const ext = url.pathname.split('.').pop()?.toLowerCase();
    findings.push({ id: 'download', severity: 'high', title: `Downloads a program (.${ext})`, detail: 'Opening it would download an app or program. Install apps only from the official app store.' });
  }
  // A second, complete address inside the first one: used to pass through a trusted site
  // (an "open redirect") on the way to a fake one.
  let redirectTo: string | null = null;
  url.searchParams.forEach((value, key) => {
    const v = value.trim();
    if (redirectTo || !/^(https?:)?\/\//i.test(v)) return;
    try {
      const inner = new URL(v.startsWith('//') ? `https:${v}` : v).hostname.toLowerCase();
      if (inner && registrableDomain(inner) !== reg) redirectTo = inner;
      else if (inner && REDIRECT_PARAMS.has(key.toLowerCase()) && inner !== host) redirectTo = inner;
    } catch {
      /* not an address */
    }
  });
  if (redirectTo) {
    findings.push({ id: 'redirect', severity: 'medium', title: 'Forwards you to another site', detail: `The address carries a second address inside it, which leads to ${truncate(redirectTo, 60)}. This trick is used to pass through a trusted site on the way to a fake one.` });
  }
  const encoded = (raw.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (/%25[0-9a-f]{2}/i.test(raw) || encoded > 15) {
    findings.push({ id: 'obfuscated', severity: 'low', title: 'Heavily encoded address', detail: 'Many encoded characters can hide what the address really says.' });
  }
  if (raw.length > 1000) {
    findings.push({ id: 'very_long', severity: 'low', title: 'Very long address', detail: 'Unusually long links can hide tracking data or a disguised destination.' });
  }

  const share = isOfficial ? SHARE_PATH.exec(url.pathname) : null;
  if (isOfficial) {
    findings.push({
      id: 'official',
      severity: 'info',
      title: 'Official TrustPass address',
      detail: share ? 'This is a TrustPass share link on the official site.' : 'This address is on the official TrustPass site.',
    });
  }

  const parts: QrUrlParts = {
    scheme: url.protocol.replace(':', ''),
    host,
    registrableDomain: reg,
    port: url.port || null,
    path: truncate(path || '/', 200),
    isOfficial,
  };
  return { parts, token: share?.[1] ?? null };
}

function summaryFor(kind: QrContentKind, verdict: QrVerdict, url: QrUrlParts | null): string {
  if (verdict === 'danger') return kind === 'script' ? 'Dangerous: this code tries to run code, not open a website.' : 'Dangerous: do not open this. It shows strong signs of phishing or malware.';
  const where = url ? ` It opens ${url.registrableDomain}.` : '';
  if (verdict === 'caution') return `Be careful: check the warnings before you continue.${where}`;
  if (kind === 'trustpass_link') return 'Genuine TrustPass share link address.';
  if (kind === 'text') return 'Plain text. It does not open anything.';
  return `No warning signs found.${where} This is not a guarantee: only continue if you trust the source.`;
}

/** Analyze the decoded text of a QR code, or a pasted link. */
export function analyzeQrContent(input: string, options: QrAnalyzeOptions): QrAnalysis {
  const content = input.replace(/^\s+|\s+$/g, '').slice(0, QR_CONTENT_MAX_LENGTH);
  const app = new URL(options.appOrigin);
  const findings: QrFinding[] = [];
  let kind: QrContentKind = 'text';
  let url: QrUrlParts | null = null;
  let token: string | null = null;
  let canOpen = false;
  const lower = content.toLowerCase();
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(content)?.[1]?.toLowerCase() ?? null;

  const finish = (): QrAnalysis => {
    const { verdict, riskScore } = verdictFor(findings);
    const order: QrSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
    findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    return {
      kind,
      verdict,
      riskScore,
      summary: summaryFor(kind, verdict, url),
      content,
      url,
      trustpassToken: token,
      findings,
      canOpen: canOpen && verdict !== 'danger',
    };
  };

  if (!content) {
    findings.push({ id: 'empty', severity: 'info', title: 'Empty', detail: 'The code contains no text.' });
    return finish();
  }

  // Code that runs instead of a page.
  if (scheme && SCRIPT_SCHEMES.has(`${scheme}:`)) {
    kind = 'script';
    findings.push({ id: 'script_scheme', severity: 'critical', title: `Runs code or opens hidden content (${scheme}:)`, detail: 'This is not a website. It can run a script, show a fake page stored inside the code, or open files on your device.' });
    return finish();
  }

  const looksLikeHost = /^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?([/?#]\S*)?$/i.test(content) && !content.includes('@');
  if (scheme === 'http' || scheme === 'https' || looksLikeHost) {
    let parsed: WhatwgUrl | null = null;
    const added = !(scheme === 'http' || scheme === 'https');
    try {
      parsed = new URL(added ? `https://${content}` : content);
    } catch {
      parsed = null;
    }
    if (parsed && parsed.hostname) {
      const r = analyzeWebUrl(content, parsed, app, findings, added);
      url = r.parts;
      token = r.token;
      kind = token ? 'trustpass_link' : 'web_link';
      canOpen = true;
      return finish();
    }
    findings.push({ id: 'malformed', severity: 'medium', title: 'Broken web address', detail: 'It looks like a link but is not a valid address.' });
    return finish();
  }

  if (scheme === 'intent' || lower.startsWith('intent://')) {
    kind = 'app_link';
    findings.push({ id: 'android_intent', severity: 'high', title: 'Opens or installs an Android app directly', detail: 'Android "intent" links can launch apps or app-store pages without showing where they lead.' });
    return finish();
  }
  if (scheme === 'wifi') {
    kind = 'wifi';
    const kv = parseKeyValues(content.slice(5));
    const ssid = kv.S ?? '(no name)';
    const type = (kv.T ?? 'nopass').toUpperCase();
    findings.push({ id: 'wifi', severity: 'info', title: `Joins the Wi-Fi network "${truncate(ssid, 40)}"`, detail: 'Only join networks you expected, such as the venue you are in.' });
    if (type === 'NOPASS' || type === '' || type === 'WEP') {
      findings.push({ id: 'wifi_weak', severity: 'medium', title: type === 'WEP' ? 'Weak Wi-Fi security (WEP)' : 'Open Wi-Fi network (no password)', detail: 'Others on this network may see or alter your traffic. Avoid signing in to anything sensitive.' });
    }
    if ((kv.H ?? '').toLowerCase() === 'true') {
      findings.push({ id: 'wifi_hidden', severity: 'low', title: 'Hidden network', detail: 'Hidden networks are unusual for public places.' });
    }
    return finish();
  }
  if (scheme === 'mailto' || lower.startsWith('matmsg:')) {
    kind = 'email';
    findings.push({ id: 'email', severity: 'info', title: 'Writes an email', detail: 'Your mail app opens with a prepared message. Check the address and the text before sending.' });
    return finish();
  }
  if (scheme === 'tel') {
    kind = 'phone';
    findings.push({ id: 'phone', severity: 'info', title: `Calls ${truncate(content.slice(4), 30)}`, detail: 'Check the number before calling. Codes in public places can lead to premium-rate numbers.' });
    return finish();
  }
  if (scheme === 'sms' || scheme === 'smsto' || scheme === 'mms') {
    kind = 'sms';
    findings.push({ id: 'sms', severity: 'medium', title: 'Sends a text message', detail: 'It prepares a message to a number chosen by whoever made the code. Messages to short or international numbers can cost money or subscribe you to services.' });
    return finish();
  }
  if (scheme === 'geo') {
    kind = 'location';
    findings.push({ id: 'geo', severity: 'info', title: 'Shows a place on a map', detail: 'It only opens your map app at a location.' });
    return finish();
  }
  if (lower.startsWith('begin:vcard') || lower.startsWith('mecard:')) {
    kind = 'contact';
    findings.push({ id: 'contact', severity: 'info', title: 'Adds a contact', detail: 'It offers to save a contact card. Check any website or number inside it before using them.' });
    return finish();
  }
  if (lower.startsWith('begin:vevent') || lower.startsWith('begin:vcalendar')) {
    kind = 'calendar';
    findings.push({ id: 'calendar', severity: 'info', title: 'Adds a calendar event', detail: 'Check any link inside the event before opening it.' });
    return finish();
  }
  if (scheme === 'otpauth' || scheme === 'otpauth-migration') {
    kind = 'authenticator';
    findings.push({ id: 'otp', severity: 'medium', title: 'Adds an account to an authenticator app', detail: 'Only scan this while setting up two-step sign-in on the service itself. Anyone holding this code can generate your sign-in codes.' });
    return finish();
  }
  if (scheme && ['bitcoin', 'ethereum', 'litecoin', 'bitcoincash', 'dogecoin', 'monero', 'tron', 'solana', 'usdt'].includes(scheme)) {
    kind = 'payment';
    findings.push({ id: 'crypto', severity: 'high', title: 'Requests a cryptocurrency payment', detail: 'Crypto payments cannot be reversed. Codes stuck over real ones in public places are a known scam.' });
    return finish();
  }
  if (scheme === 'itms-services') {
    kind = 'app_link';
    findings.push({ id: 'ios_enterprise_app', severity: 'high', title: 'Installs an iPhone app from outside the App Store', detail: 'These links install apps that Apple has not reviewed. Install apps only from the App Store.' });
    return finish();
  }
  if (scheme && (APP_SCHEMES.has(scheme) || content.slice(scheme.length + 1).startsWith('//'))) {
    kind = 'app_link';
    findings.push({ id: 'app_scheme', severity: 'medium', title: `Opens an app (${scheme}:)`, detail: 'It opens an app on your phone instead of a website. Only continue if you know which app and why.' });
    return finish();
  }

  // Plain text, possibly with a link inside.
  kind = 'text';
  const embedded = /https?:\/\/[^\s<>"']+/i.exec(content)?.[0];
  if (embedded) {
    const inner = analyzeQrContent(embedded, options);
    findings.push({ id: 'embedded_link', severity: inner.verdict === 'danger' ? 'high' : inner.verdict === 'caution' ? 'medium' : 'info', title: 'Contains a link in the text', detail: `The text includes ${truncate(embedded, 60)}. ${inner.summary}` });
  } else if (BIDI_OR_INVISIBLE.test(content)) {
    findings.push({ id: 'hidden_chars', severity: 'medium', title: 'Hidden or direction-reversing characters', detail: 'The text contains invisible characters that can change how it reads.' });
  }
  return finish();
}

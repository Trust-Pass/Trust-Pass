import { analyzeQrContent, type QrAnalysis } from '@trustpass/shared';
import { describe, expect, it } from 'vitest';

const opts = { appOrigin: 'https://trustpass-gwnp.onrender.com' };
const check = (content: string) => analyzeQrContent(content, opts);
const ids = (a: QrAnalysis) => a.findings.map((f) => f.id);
const TOKEN = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd';

describe('QR Shield: safe content', () => {
  it.each([
    'https://www.google.com/search?q=trustpass',
    'https://imamu.edu.sa/',
    'https://www.alrajhibank.com.sa/en',
    'https://github.com/Trust-Pass/Trust-Pass',
    'https://ample.com/', // one letter from "apple": short names are not fuzzy-matched
  ])('%s has no warnings', (content) => {
    const a = check(content);
    expect(a.verdict).toBe('safe');
    expect(a.kind).toBe('web_link');
    expect(a.canOpen).toBe(true);
  });

  it('recognises an official TrustPass share link and extracts its token', () => {
    const a = check(`https://trustpass-gwnp.onrender.com/s/${TOKEN}`);
    expect(a).toMatchObject({ kind: 'trustpass_link', verdict: 'safe', trustpassToken: TOKEN });
    expect(a.url).toMatchObject({ host: 'trustpass-gwnp.onrender.com', isOfficial: true });
    expect(ids(a)).toContain('official');
  });

  it('a local or self-hosted official address is not flagged as a local device', () => {
    const local = analyzeQrContent(`http://localhost:5173/s/${TOKEN}`, { appOrigin: 'http://localhost:5173' });
    expect(local).toMatchObject({ kind: 'trustpass_link', verdict: 'safe', trustpassToken: TOKEN });
    const other = analyzeQrContent('http://localhost:9999/', { appOrigin: 'http://localhost:5173' });
    expect(other.findings.map((f) => f.id)).toContain('private_ip');
  });

  it('treats an address without http(s) as a web link', () => {
    const a = check('example.com/menu');
    expect(a.kind).toBe('web_link');
    expect(a.url?.scheme).toBe('https');
    expect(ids(a)).toContain('no_scheme');
  });

  it('treats ordinary text as text, even with a colon in it', () => {
    const a = check('Note: the meeting is at 10');
    expect(a).toMatchObject({ kind: 'text', verdict: 'safe', canOpen: false, url: null });
  });

  it('finds the registrable domain under two-label suffixes', () => {
    expect(check('https://portal.imamu.edu.sa/x').url?.registrableDomain).toBe('imamu.edu.sa');
    expect(check('https://shop.example.co.uk/').url?.registrableDomain).toBe('example.co.uk');
  });
});

describe('QR Shield: phishing and malware signs', () => {
  it.each([
    ['https://paypa1-secure.com/login', 'brand_lookalike'],
    ['https://paypal.com.account-verify.xyz/signin', 'brand_lookalike'],
    ['https://absher-sa.com/update', 'brand_lookalike'],
    ['https://gooogle.com/', 'brand_lookalike'],
    ['https://trustpass-verify.onrender.com/s/AbCdEfGhIjKlMnOpQrStUvWxYz0123', 'trustpass_lookalike'],
    ['https://www.paypal.com@evil.example/login', 'userinfo'],
    ['http://45.33.32.156/payload', 'ip_address'],
    ['http://192.168.1.1/admin', 'private_ip'],
    ['http://[::1]:8080/', 'private_ip'],
    ['https://xn--pple-43d.com/', 'punycode'],
    ['https://example.com/app/WhatsApp.apk', 'download'],
    ['https://example.com/setup.exe?x=1', 'download'],
  ])('%s is dangerous (%s)', (content, finding) => {
    const a = check(content);
    expect(a.verdict).toBe('danger');
    expect(ids(a)).toContain(finding);
    expect(a.canOpen).toBe(false);
  });

  it('a decimal IP address is normalised and still caught', () => {
    const a = check('http://3232235777/');
    expect(['danger']).toContain(a.verdict);
    expect(ids(a)).toContain('private_ip');
  });

  it('script and data links are critical and can never be opened', () => {
    for (const c of ['javascript:alert(document.cookie)', 'JaVaScRiPt:alert(1)', 'data:text/html;base64,PHNjcmlwdD4=', 'file:///etc/passwd', 'vbscript:msgbox']) {
      const a = check(c);
      expect(a).toMatchObject({ kind: 'script', verdict: 'danger', canOpen: false });
      expect(a.findings[0]?.severity).toBe('critical');
    }
  });

  it('hidden direction-reversing characters are flagged', () => {
    expect(ids(check('https://example.com/‮gpj.exe'))).toContain('hidden_chars');
  });
});

describe('QR Shield: caution signs', () => {
  it.each([
    ['http://example.com/menu', 'not_https'],
    ['https://bit.ly/3xYzAbc', 'shortener'],
    ['https://example.com:8443/', 'unusual_port'],
    ['https://some-shop.netlify.app/', 'shared_hosting'],
    ['https://example.xyz/', 'risky_tld'],
    ['https://www.google.com/url?q=https://evil.example/login', 'redirect'],
  ])('%s needs caution (%s)', (content, finding) => {
    const a = check(content);
    expect(a.verdict).toBe('caution');
    expect(ids(a)).toContain(finding);
    expect(a.canOpen).toBe(true);
  });

  it('several medium signs together become dangerous', () => {
    const a = check('http://free-gift.netlify.app:8080/claim?next=https://x.example');
    expect(a.verdict).toBe('danger');
  });

  it('http on the official host is not "official"', () => {
    const a = check(`http://trustpass-gwnp.onrender.com/s/${TOKEN}`);
    expect(a.url?.isOfficial).toBe(false);
    expect(a.trustpassToken).toBeNull();
    expect(ids(a)).toContain('not_https');
  });
});

describe('QR Shield: other QR code types', () => {
  it('Wi-Fi: shows the network, never the password; open networks need caution', () => {
    const wpa = check('WIFI:T:WPA;S:Cafe Guest;P:secret123;;');
    expect(wpa).toMatchObject({ kind: 'wifi', verdict: 'safe', canOpen: false });
    expect(JSON.stringify(wpa.findings)).not.toContain('secret123');
    expect(wpa.findings[0]?.title).toContain('Cafe Guest');
    expect(check('WIFI:T:nopass;S:Free_WiFi;;')).toMatchObject({ kind: 'wifi', verdict: 'caution' });
    expect(check('WIFI:S:My\\;Net;T:WEP;P:x;;').findings.map((f) => f.title).join()).toContain('My;Net');
  });

  it.each([
    ['mailto:reham@example.com', 'email', 'safe'],
    ['tel:+966112345678', 'phone', 'safe'],
    ['geo:24.7136,46.6753', 'location', 'safe'],
    ['BEGIN:VCARD\nVERSION:3.0\nFN:Reham\nEND:VCARD', 'contact', 'safe'],
    ['SMSTO:+966500000000:Subscribe', 'sms', 'caution'],
    ['otpauth://totp/Acme:reham?secret=JBSWY3DPEHPK3PXP', 'authenticator', 'caution'],
    ['whatsapp://send?text=hi', 'app_link', 'caution'],
    ['bitcoin:bc1qxyz?amount=0.5', 'payment', 'danger'],
    ['intent://scan/#Intent;scheme=zxing;package=com.example;end', 'app_link', 'danger'],
    ['itms-services://?action=download-manifest&url=https://x.example/m.plist', 'app_link', 'danger'],
  ])('%s → %s / %s', (content, kind, verdict) => {
    const a = check(content);
    expect(a.kind).toBe(kind);
    expect(a.verdict).toBe(verdict);
    expect(a.canOpen).toBe(false);
  });

  it('text with a dangerous link inside is dangerous', () => {
    const a = check('Claim your prize: https://amazon-gift-claim.top/prize');
    expect(a).toMatchObject({ kind: 'text', verdict: 'danger' });
    expect(ids(a)).toContain('embedded_link');
  });

  it('empty and oversized input are handled', () => {
    expect(check('   ').verdict).toBe('safe');
    expect(check(`https://example.com/${'a'.repeat(10_000)}`).content.length).toBe(4096);
  });
});

import type { QrAnalysis, QrSeverity, QrSource } from '@trustpass/shared';
import clsx from 'clsx';
import {
  AlertTriangle,
  Camera,
  CameraOff,
  ClipboardPaste,
  ExternalLink,
  ImagePlus,
  Info,
  Lock,
  LockOpen,
  QrCode,
  RotateCcw,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { Alert, Badge, Button, Card, CardHeader, ConfirmModal, CopyButton, PageHeader, Tabs, Textarea } from '../components/ui';
import { api, errorMessage } from '../lib/api';
import { CAMERA_PROBLEM_TEXT, cameraProblem, decodeCanvas, decodeImageFile, drawScaled, releaseQrDecoder, type CameraProblem } from '../lib/qr';

type Analysis = Omit<QrAnalysis, 'trustpassToken'>;
type LinkStatus = 'active' | 'expired' | 'revoked' | 'not_found';
interface CheckResponse {
  analysis: Analysis;
  trustpassLink: { status: LinkStatus } | null;
}

const KIND_LABEL: Record<QrAnalysis['kind'], string> = {
  trustpass_link: 'TrustPass link',
  web_link: 'Website link',
  script: 'Script',
  app_link: 'App link',
  wifi: 'Wi-Fi network',
  email: 'Email',
  phone: 'Phone call',
  sms: 'Text message',
  location: 'Map location',
  contact: 'Contact card',
  calendar: 'Calendar event',
  authenticator: 'Authenticator setup',
  payment: 'Crypto payment',
  text: 'Text',
};

const VERDICT_UI = {
  safe: { title: 'No warning signs found', icon: ShieldCheck, box: 'bg-teal-50 ring-teal-200 text-teal-950', iconBox: 'bg-teal-600', bar: 'bg-teal-500' },
  caution: { title: 'Be careful', icon: ShieldAlert, box: 'bg-amber-50 ring-amber-200 text-amber-950', iconBox: 'bg-amber-500', bar: 'bg-amber-500' },
  danger: { title: 'Dangerous: do not open', icon: ShieldX, box: 'bg-red-50 ring-red-200 text-red-950', iconBox: 'bg-red-600', bar: 'bg-red-600' },
} as const;

const SEVERITY_UI: Record<QrSeverity, { label: string; tone: 'red' | 'amber' | 'slate' | 'navy'; icon: ReactNode }> = {
  critical: { label: 'Critical', tone: 'red', icon: <ShieldX className="size-4 text-red-600" /> },
  high: { label: 'High', tone: 'red', icon: <AlertTriangle className="size-4 text-red-600" /> },
  medium: { label: 'Medium', tone: 'amber', icon: <AlertTriangle className="size-4 text-amber-600" /> },
  low: { label: 'Low', tone: 'slate', icon: <Info className="size-4 text-slate-500" /> },
  info: { label: 'Info', tone: 'navy', icon: <Info className="size-4 text-navy-500" /> },
};

const LINK_STATUS_UI: Record<LinkStatus, { label: string; tone: 'green' | 'amber' | 'red' }> = {
  active: { label: 'Active link', tone: 'green' },
  expired: { label: 'Expired', tone: 'amber' },
  revoked: { label: 'Revoked', tone: 'amber' },
  not_found: { label: 'Does not exist', tone: 'red' },
};

// ---------------------------------------------------------------------------
// Camera
// ---------------------------------------------------------------------------

function CameraScanner({ onDecoded, disabled }: { onDecoded: (text: string) => void; disabled: boolean }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<number | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [state, setState] = useState<'idle' | 'starting' | 'scanning'>('idle');
  const [problem, setProblem] = useState<CameraProblem | null>(null);

  const stop = useCallback(() => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    timerRef.current = null;
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
    setState('idle');
  }, []);

  useEffect(() => stop, [stop]);

  const scanFrame = useCallback(async () => {
    const video = videoRef.current;
    if (!video || !streamRef.current) return;
    if (video.readyState >= 2 && video.videoWidth > 0) {
      canvasRef.current = drawScaled(video, video.videoWidth, video.videoHeight, 800, canvasRef.current ?? undefined);
      const text = await decodeCanvas(canvasRef.current, { fast: true });
      if (!streamRef.current) return;
      if (text) {
        if (navigator.vibrate) navigator.vibrate(60);
        stop();
        onDecoded(text);
        return;
      }
    }
    timerRef.current = window.setTimeout(() => void scanFrame(), 200);
  }, [onDecoded, stop]);

  const start = async () => {
    setProblem(null);
    if (!window.isSecureContext) return setProblem('insecure');
    if (!navigator.mediaDevices?.getUserMedia) return setProblem('unsupported');
    setState('starting');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      streamRef.current = stream;
      const video = videoRef.current;
      if (!video) return stop();
      video.srcObject = stream;
      await video.play();
      setState('scanning');
      void scanFrame();
    } catch (err) {
      stop();
      setProblem(cameraProblem(err));
    }
  };

  return (
    <div className="space-y-3">
      <div className="relative aspect-[4/3] overflow-hidden rounded-2xl bg-navy-950">
        <video ref={videoRef} className={clsx('size-full object-cover', state === 'idle' && 'hidden')} playsInline muted aria-label="Camera preview" />
        {state === 'scanning' && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center" aria-hidden>
            <div className="relative size-3/5 max-w-64 rounded-2xl border-2 border-white/80 shadow-[0_0_0_9999px_rgba(2,6,23,0.45)]">
              <ScanLine className="absolute left-1/2 top-1/2 size-10 -translate-x-1/2 -translate-y-1/2 animate-pulse text-teal-300" />
            </div>
          </div>
        )}
        {state !== 'scanning' && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 px-6 text-center text-navy-100">
            {problem ? <CameraOff className="size-9 text-navy-300" /> : <QrCode className="size-10 text-navy-300" />}
            <p className="text-sm">{state === 'starting' ? 'Starting the camera…' : 'Point your camera at a QR code. It is read on this device; no photo is uploaded.'}</p>
          </div>
        )}
      </div>
      {problem && <Alert tone="warning">{CAMERA_PROBLEM_TEXT[problem]}</Alert>}
      {state === 'scanning' ? (
        <Button variant="secondary" size="lg" className="w-full" onClick={stop} icon={<CameraOff className="size-5" />}>
          Stop camera
        </Button>
      ) : (
        <Button size="lg" className="w-full" onClick={() => void start()} loading={state === 'starting'} disabled={disabled} icon={<Camera className="size-5" />}>
          Start camera
        </Button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

function ResultPanel({ result, onReset }: { result: CheckResponse; onReset: () => void }) {
  const navigate = useNavigate();
  const { analysis, trustpassLink } = result;
  const ui = VERDICT_UI[analysis.verdict];
  const Icon = ui.icon;
  const [confirmOpen, setConfirmOpen] = useState(false);
  const isOwnLink = analysis.kind === 'trustpass_link' && analysis.url?.isOfficial;

  const open = () => {
    setConfirmOpen(false);
    if (!analysis.url || !analysis.canOpen) return;
    let target: URL;
    try {
      target = new URL(/^https?:\/\//i.test(analysis.content) ? analysis.content : `https://${analysis.content}`);
    } catch {
      return;
    }
    // Only ever web addresses: never javascript:, data: or app links.
    if (target.protocol !== 'https:' && target.protocol !== 'http:') return;
    if (isOwnLink) navigate(`${target.pathname}${target.search}${target.hash}`);
    else window.open(target.href, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="space-y-4" data-testid="qr-result">
      <div className={clsx('rounded-2xl p-4 ring-1 ring-inset sm:p-5', ui.box)} data-testid="qr-verdict" data-verdict={analysis.verdict}>
        <div className="flex items-start gap-3">
          <span className={clsx('flex size-11 shrink-0 items-center justify-center rounded-xl text-white', ui.iconBox)}>
            <Icon className="size-6" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-lg font-semibold">{ui.title}</p>
            <p className="mt-0.5 text-sm leading-relaxed opacity-90">{analysis.summary}</p>
          </div>
        </div>
        <div className="mt-4" aria-label={`Risk score ${analysis.riskScore} out of 100`}>
          <div className="flex justify-between text-xs font-medium opacity-80">
            <span>Risk</span>
            <span>{analysis.riskScore}/100</span>
          </div>
          <div className="mt-1 h-2 overflow-hidden rounded-full bg-white/70">
            <div className={clsx('h-full rounded-full transition-all', ui.bar)} style={{ width: `${Math.max(4, analysis.riskScore)}%` }} />
          </div>
        </div>
      </div>

      <Card>
        <CardHeader
          title="What the code contains"
          subtitle="Shown as text only. Nothing has been opened."
          action={<Badge tone="navy">{KIND_LABEL[analysis.kind]}</Badge>}
        />
        <div className="space-y-3 px-4 pb-4 sm:px-5 sm:pb-5">
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-xl bg-slate-50 p-3 font-mono text-[13px] leading-relaxed text-navy-950 ring-1 ring-inset ring-slate-200" data-testid="qr-content">
            {analysis.content}
          </pre>
          {analysis.url && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-slate-500">Site</dt>
              <dd className="flex min-w-0 flex-wrap items-center gap-2">
                <span className="break-all font-semibold text-navy-950" data-testid="qr-domain">{analysis.url.registrableDomain}</span>
                {analysis.url.isOfficial && <Badge tone="teal" icon={<ShieldCheck className="size-3.5" />}>Official TrustPass</Badge>}
                {trustpassLink && <Badge tone={LINK_STATUS_UI[trustpassLink.status].tone}>{LINK_STATUS_UI[trustpassLink.status].label}</Badge>}
              </dd>
              <dt className="text-slate-500">Full host</dt>
              <dd className="break-all text-navy-950">{analysis.url.host}{analysis.url.port ? `:${analysis.url.port}` : ''}</dd>
              <dt className="text-slate-500">Connection</dt>
              <dd className="flex items-center gap-1.5 text-navy-950">
                {analysis.url.scheme === 'https' ? <Lock className="size-4 text-teal-600" /> : <LockOpen className="size-4 text-amber-600" />}
                {analysis.url.scheme === 'https' ? 'Encrypted (https)' : `Not encrypted (${analysis.url.scheme})`}
              </dd>
            </dl>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader title="Checks" subtitle={analysis.findings.length === 0 ? 'Nothing to report.' : `${analysis.findings.filter((f) => f.severity !== 'info').length} warning(s)`} />
        <ul className="divide-y divide-slate-100" data-testid="qr-findings">
          {analysis.findings.map((f) => (
            <li key={f.id} className="flex gap-3 px-4 py-3 sm:px-5" data-finding={f.id}>
              <span className="mt-0.5 shrink-0">{SEVERITY_UI[f.severity].icon}</span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-sm font-semibold text-navy-950">{f.title}</p>
                  {f.severity !== 'info' && <Badge tone={SEVERITY_UI[f.severity].tone}>{SEVERITY_UI[f.severity].label}</Badge>}
                </div>
                <p className="mt-0.5 text-sm leading-relaxed text-slate-600">{f.detail}</p>
              </div>
            </li>
          ))}
        </ul>
      </Card>

      <div className="flex flex-col gap-2 sm:flex-row">
        {analysis.canOpen && (
          <Button
            variant={analysis.verdict === 'safe' ? 'primary' : 'secondary'}
            className="sm:flex-1"
            icon={<ExternalLink className="size-4" />}
            onClick={() => (analysis.verdict === 'safe' ? open() : setConfirmOpen(true))}
          >
            {isOwnLink ? 'Open in TrustPass' : analysis.verdict === 'safe' ? 'Open link' : 'Open anyway'}
          </Button>
        )}
        <CopyButton value={analysis.content} label="Copy text" size="md" />
        <Button variant="ghost" icon={<RotateCcw className="size-4" />} onClick={onReset}>
          Check another
        </Button>
      </div>
      {analysis.verdict === 'danger' && (
        <p className="text-sm text-slate-600">Opening is turned off for dangerous content. If you received this code from someone you know, ask them about it another way.</p>
      )}

      <ConfirmModal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={open}
        title="Open this link?"
        confirmLabel="Open in a new tab"
        body={
          <>
            TrustPass found warning signs for <strong className="break-all text-navy-950">{analysis.url?.registrableDomain}</strong>. Do not enter passwords, card details or
            verification codes unless you are sure the site is genuine.
          </>
        }
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function QrScannerPage() {
  const [mode, setMode] = useState<QrSource>('camera');
  const [pasted, setPasted] = useState('');
  const [imageName, setImageName] = useState<string | null>(null);
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => releaseQrDecoder, []);

  const check = useCallback(async (content: string, source: QrSource) => {
    setError(null);
    setBusy(true);
    try {
      setResult(await api<CheckResponse>('/api/qr/check', { body: { content, source } }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }, []);

  const onCamera = useCallback((text: string) => void check(text, 'camera'), [check]);

  const onImage = async (file: File | undefined) => {
    if (!file) return;
    setImageName(file.name);
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const text = await decodeImageFile(file);
      if (!text) {
        setError('No QR code was found in this image. Try a sharper photo, closer to the code, or crop it.');
        setBusy(false);
        return;
      }
      await check(text, 'image');
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    } finally {
      if (fileInput.current) fileInput.current.value = '';
    }
  };

  const onPaste = (e: FormEvent) => {
    e.preventDefault();
    const text = pasted.trim();
    if (!text) return setError('Paste a link or the text of a QR code first.');
    void check(text, 'paste');
  };

  const reset = () => {
    setResult(null);
    setError(null);
    setImageName(null);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="QR Security Scanner"
        description="Check a QR code or a link before you open it. Codes are read on this device, and the address is checked without visiting it."
      />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="p-4 sm:p-5">
          <Tabs
            value={mode}
            onChange={(m) => {
              setMode(m);
              reset();
            }}
            tabs={[
              { value: 'camera', label: 'Camera' },
              { value: 'image', label: 'Image' },
              { value: 'paste', label: 'Paste a link' },
            ]}
          />
          <div className="mt-4 space-y-4">
            {mode === 'camera' && <CameraScanner onDecoded={onCamera} disabled={busy} />}
            {mode === 'image' && (
              <>
                <button
                  type="button"
                  onClick={() => fileInput.current?.click()}
                  disabled={busy}
                  className="flex w-full flex-col items-center rounded-2xl border-2 border-dashed border-slate-300 px-4 py-10 text-center transition-colors hover:border-navy-300 hover:bg-slate-50 disabled:opacity-60"
                >
                  <ImagePlus className="size-8 text-navy-600" />
                  <span className="mt-2 font-semibold text-navy-950">{imageName ?? 'Choose a photo or screenshot'}</span>
                  <span className="mt-1 text-sm text-slate-500">PNG, JPEG or WebP. The image stays on this device; only the decoded text is checked.</span>
                </button>
                <input
                  ref={fileInput}
                  type="file"
                  accept="image/*"
                  className="sr-only"
                  aria-label="QR code image"
                  data-testid="qr-image-input"
                  onChange={(e) => void onImage(e.target.files?.[0])}
                />
              </>
            )}
            {mode === 'paste' && (
              <form onSubmit={onPaste} className="space-y-3">
                <label htmlFor="qr-paste" className="block text-sm font-medium text-navy-950">
                  Link or QR code text
                </label>
                <Textarea
                  id="qr-paste"
                  value={pasted}
                  onChange={(e) => setPasted(e.target.value)}
                  rows={4}
                  maxLength={4096}
                  placeholder="https://…"
                  spellCheck={false}
                  autoCapitalize="off"
                  autoCorrect="off"
                />
                <Button type="submit" size="lg" className="w-full" loading={busy} icon={<ClipboardPaste className="size-5" />}>
                  Check
                </Button>
              </form>
            )}
            {busy && mode !== 'paste' && <p className="text-sm text-slate-500">Checking…</p>}
            {error && <Alert tone="error">{error}</Alert>}
          </div>
        </Card>

        <div>
          {result ? (
            <ResultPanel result={result} onReset={reset} />
          ) : (
            <Card className="p-5">
              <h2 className="font-semibold text-navy-950">What TrustPass checks</h2>
              <ul className="mt-3 space-y-2.5 text-sm text-slate-600">
                {[
                  'Fake names that imitate banks, government services, delivery companies and TrustPass itself',
                  'Disguised addresses: raw IP numbers, look-alike international letters, text before "@"',
                  'Hidden destinations: short links and addresses that forward you elsewhere',
                  'Unencrypted sites, unusual ports and domain endings common in scams',
                  'Downloads of apps or programs from outside the app store',
                  'Codes that run scripts, send texts, request crypto payments or join Wi-Fi networks',
                  'TrustPass share links: whether the link is genuine and still active',
                ].map((t) => (
                  <li key={t} className="flex gap-2.5">
                    <ShieldCheck className="mt-0.5 size-4 shrink-0 text-teal-600" />
                    {t}
                  </li>
                ))}
              </ul>
              <p className="mt-4 text-[13px] text-slate-500">
                A clean result means no warning signs were found, not that a site is guaranteed safe. When in doubt, type the address of the organization yourself.
              </p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

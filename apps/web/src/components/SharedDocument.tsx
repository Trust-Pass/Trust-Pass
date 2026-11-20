import { Clock, Download, Eye, FileText, Info, MapPin, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { country, formatDateTime, relativeTime } from '../lib/format';
import type { SharedView } from '../lib/types';
import { LazyPdfViewer } from './LazyPdfViewer';
import { Badge, Card, CardHeader, CopyButton } from './ui';
import { VerificationPanel } from './VerificationPanel';

/** What a recipient sees: only the disclosed fields, the verification result and, if shared, the watermarked file. */
export function SharedDocument({ view, fileUrl }: { view: SharedView; fileUrl: string }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [lastCopy, setLastCopy] = useState<string | null>(null);

  // Every download is a new request: the server re-checks expiry, revocation and country first,
  // then generates a separate watermarked copy for this recipient.
  const downloadCopy = async () => {
    setDownloading(true);
    setDownloadError(null);
    try {
      const res = await fetch(fileUrl.replace(/\/file$/, '/download'), { credentials: 'include', cache: 'no-store' });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null;
        throw new Error(body?.error?.message ?? 'The download is not available.');
      }
      const ref = res.headers.get('X-TrustPass-Copy') ?? 'copy';
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `trustpass-copy-${ref}.pdf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setLastCopy(ref);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : 'The download is not available.');
    } finally {
      setDownloading(false);
    }
  };

  const downloadPresentation = () => {
    if (!view.presentation) return;
    const blob = new Blob([view.presentation], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'trustpass-presentation.sdjwt.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <Card className="overflow-hidden">
        <div className="hero-grid border-b border-white/[0.06] px-4 py-5 text-white sm:px-6">
          <p className="text-sm text-navy-200">
            Shared by <span className="font-semibold text-white">{view.link.sharedBy}</span> with{' '}
            <span className="font-semibold text-white">{view.link.recipientOrg ?? view.link.recipientLabel}</span>
          </p>
          <h1 className="mt-1 text-xl font-bold sm:text-2xl">{view.document.title}</h1>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge tone="navy" icon={<Eye className="size-3.5" />}>
              View only
            </Badge>
            <Badge tone="navy" icon={<Clock className="size-3.5" />}>
              Expires {relativeTime(view.link.expiresAt)}
            </Badge>
          </div>
        </div>
        <div className="space-y-4 p-4 sm:p-6">
          <VerificationPanel verification={view.verification} />

          <div>
            <h2 className="mb-2 text-sm font-semibold text-ink">
              {view.fields.length > 0 ? 'Information shared with you' : 'The owner shared the file below, not individual fields'}
            </h2>
            {view.fields.length > 0 && (
              <dl className="divide-y divide-slate-100 rounded-xl ring-1 ring-slate-200" data-testid="shared-fields">
                {view.fields.map((f) => (
                  <div key={f.label} className="flex flex-col gap-0.5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                    <dt className="text-sm text-slate-500">{f.label}</dt>
                    <dd className="flex items-center gap-2 font-semibold text-ink">
                      {f.value}
                      {f.source === 'issuer' ? (
                        <ShieldCheck className="size-4 text-teal-400" aria-label="Signed by the issuer" />
                      ) : (
                        <Badge tone="amber">Self-declared</Badge>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
            {view.fields.length > 0 && (
              <p className="mt-2 text-[13px] text-slate-500">
                Only the fields the owner chose are sent to your device. Everything else in the document stays encrypted on the server.
              </p>
            )}
          </div>

          {view.presentation && (
            <div className="rounded-xl bg-slate-50 p-4 ring-1 ring-slate-200">
              <p className="text-sm font-semibold text-ink">Verify it yourself</p>
              <p className="mt-0.5 text-[13px] text-slate-600">
                This is the signed credential with only the shared fields (SD-JWT). Paste it into any TrustPass Verification page to check the issuer signature independently.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyButton value={view.presentation} label="Copy credential" />
                <button type="button" onClick={downloadPresentation} className="inline-flex h-9 items-center gap-1.5 rounded-xl px-3 text-sm font-medium text-ink ring-1 ring-slate-300 hover:bg-surface">
                  <Download className="size-4" /> Download
                </button>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-2 text-[13px] text-slate-600 sm:grid-cols-2">
            <p className="flex items-center gap-2">
              <MapPin className="size-4 shrink-0 text-slate-400" /> Your approximate location: {country(view.viewer.approximateCountry)}
            </p>
            <p className="flex items-center gap-2">
              <Clock className="size-4 shrink-0 text-slate-400" /> Link expires {formatDateTime(view.link.expiresAt)}
            </p>
          </div>
        </div>
      </Card>

      {view.document.fileShared && (
        <Card>
          <CardHeader
            title="Document"
            subtitle={`${view.document.fileMode === 'redacted' ? 'Redacted copy: the owner hid parts of this document. ' : ''}${view.document.watermarked === false ? '' : 'Watermarked for you. '}${view.document.downloadAllowed ? 'You can download a copy.' : 'Downloads are disabled.'}`}
            icon={<FileText className="size-5" />}
          />
          {view.document.downloadAllowed && (
            <div className="space-y-2 border-b border-slate-100 px-4 py-3 sm:px-6" data-testid="download-panel">
              <button
                type="button"
                onClick={downloadCopy}
                disabled={downloading}
                data-testid="download-copy"
                className="inline-flex h-10 items-center gap-2 rounded-xl bg-accent px-4 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-60"
              >
                <Download className="size-4" /> {downloading ? 'Preparing your copy…' : view.document.watermarked === false ? 'Download PDF' : 'Download watermarked PDF'}
              </button>
              <p className="text-[13px] text-slate-500">
                {view.document.watermarked === false
                  ? 'The owner chose no watermark. The download is logged for the owner.'
                  : 'Your name, the time and a unique copy reference are printed on every page. The download is logged for the owner.'}
              </p>
              {lastCopy && <p className="text-[13px] text-teal-400" data-testid="download-done">Downloaded copy {lastCopy}.</p>}
              {downloadError && <p className="text-[13px] text-red-500" role="alert" data-testid="download-error">{downloadError}</p>}
            </div>
          )}
          <div className="bg-slate-100/70 p-3 sm:p-5">
            <LazyPdfViewer src={fileUrl} label={view.document.title} />
          </div>
        </Card>
      )}

      <div className="flex gap-3 rounded-xl bg-surface p-4 text-[13px] leading-relaxed text-slate-600 ring-1 ring-slate-200">
        <Info className="mt-0.5 size-4 shrink-0 text-accent" />
        <p>{view.notice} Every view is logged for the owner with an approximate country, never your full IP address.</p>
      </div>
    </div>
  );
}

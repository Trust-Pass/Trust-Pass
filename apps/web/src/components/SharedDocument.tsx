import { Clock, Download, Eye, FileText, Info, MapPin, ShieldCheck } from 'lucide-react';
import { country, formatDateTime, relativeTime } from '../lib/format';
import type { SharedView } from '../lib/types';
import { LazyPdfViewer } from './LazyPdfViewer';
import { Badge, Card, CardHeader, CopyButton } from './ui';
import { VerificationPanel } from './VerificationPanel';

/** What a recipient sees: only the disclosed fields, the verification result and, if shared, the watermarked file. */
export function SharedDocument({ view, fileUrl }: { view: SharedView; fileUrl: string }) {
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
        <div className="bg-navy-900 px-4 py-5 text-white sm:px-6">
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
            <h2 className="mb-2 text-sm font-semibold text-navy-950">
              {view.fields.length > 0 ? 'Information shared with you' : 'The owner shared the file below, not individual fields'}
            </h2>
            {view.fields.length > 0 && (
              <dl className="divide-y divide-slate-100 rounded-xl ring-1 ring-slate-200" data-testid="shared-fields">
                {view.fields.map((f) => (
                  <div key={f.label} className="flex flex-col gap-0.5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                    <dt className="text-sm text-slate-500">{f.label}</dt>
                    <dd className="flex items-center gap-2 font-semibold text-navy-950">
                      {f.value}
                      {f.source === 'issuer' ? (
                        <ShieldCheck className="size-4 text-teal-600" aria-label="Signed by the issuer" />
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
              <p className="text-sm font-semibold text-navy-950">Verify it yourself</p>
              <p className="mt-0.5 text-[13px] text-slate-600">
                This is the signed credential with only the shared fields (SD-JWT). Paste it into any TrustPass Verification page to check the issuer signature independently.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyButton value={view.presentation} label="Copy credential" />
                <button type="button" onClick={downloadPresentation} className="inline-flex h-9 items-center gap-1.5 rounded-xl px-3 text-sm font-medium text-navy-800 ring-1 ring-slate-300 hover:bg-white">
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
          <CardHeader title="Document" subtitle="Watermarked for you. Downloads are disabled." icon={<FileText className="size-5" />} />
          <div className="bg-slate-100/70 p-3 sm:p-5">
            <LazyPdfViewer src={fileUrl} label={view.document.title} />
          </div>
        </Card>
      )}

      <div className="flex gap-3 rounded-xl bg-white p-4 text-[13px] leading-relaxed text-slate-600 ring-1 ring-slate-200">
        <Info className="mt-0.5 size-4 shrink-0 text-navy-500" />
        <p>{view.notice} Every view is logged for the owner with an approximate country, never your full IP address.</p>
      </div>
    </div>
  );
}

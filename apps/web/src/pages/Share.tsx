import { DEFAULT_WATERMARK, EXPIRY_LABELS, REDACTION_MAX_TOTAL_BYTES, WATERMARK_STYLE_LABELS, type Redaction, type WatermarkSettings } from '@trustpass/shared';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowLeft, Building2, Clock, Download, Eye, ExternalLink, FileText, Globe2, ListChecks, RefreshCw, Send, Share2, Stamp, Users, X } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { CountryPicker } from '../components/CountryPicker';
import { LazyPdfViewer } from '../components/LazyPdfViewer';
import { RedactionEditor, type RedactionEditorHandle } from '../components/RedactionEditor';
import { WatermarkControls } from '../components/WatermarkControls';
import { Alert, Badge, Button, ButtonLink, Card, CopyButton, Field, Input, PageHeader, Segmented, Spinner, Toggle } from '../components/ui';
import { api, ApiError, apiPostBlob, errorMessage } from '../lib/api';
import { flag, formatDateTime } from '../lib/format';
import type { DocumentDetail } from '../lib/types';
import { Seal } from '../components/Seal';

type Expiry = '1h' | '24h' | '3d' | '7d' | 'custom';

function Step({ n, title, icon, children }: { n: number; title: string; icon: ReactNode; children: ReactNode }) {
  return (
    <Card className="p-4 sm:p-5">
      <div className="mb-4 flex items-center gap-2.5">
        <span className="flex size-7 items-center justify-center rounded-full btn-primary text-xs font-bold shadow-glow">{n}</span>
        <h2 className="flex items-center gap-2 font-semibold text-ink">
          {icon}
          {title}
        </h2>
      </div>
      {children}
    </Card>
  );
}

function OrgSearch({ value, onChange }: { value: { id: string; name: string } | null; onChange: (org: { id: string; name: string } | null) => void }) {
  const [q, setQ] = useState('');
  const { data } = useQuery({
    queryKey: ['org-directory', q],
    queryFn: () => api<{ organizations: Array<{ id: string; name: string; type: string }> }>(`/api/organizations/directory?q=${encodeURIComponent(q)}`),
    enabled: !value,
  });
  if (value) {
    return (
      <div className="flex items-center justify-between rounded-xl bg-accent-soft px-3.5 py-2.5 ring-1 ring-accent-line">
        <span className="flex items-center gap-2 font-medium text-ink">
          <Building2 className="size-4" /> {value.name}
        </span>
        <button type="button" className="text-sm font-medium text-accent underline" onClick={() => onChange(null)}>
          Change
        </button>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search organizations on TrustPass" aria-label="Search organizations" />
      <ul className="max-h-52 overflow-y-auto rounded-xl ring-1 ring-slate-200">
        {(data?.organizations ?? []).map((o) => (
          <li key={o.id}>
            <button type="button" onClick={() => onChange(o)} className="flex w-full items-center justify-between px-3.5 py-2.5 text-left text-sm hover:bg-slate-50">
              <span className="font-medium text-ink">{o.name}</span>
              <span className="text-xs text-slate-500 capitalize">{o.type}</span>
            </button>
          </li>
        ))}
        {data && data.organizations.length === 0 && <li className="px-3.5 py-3 text-sm text-slate-500">No organizations match.</li>}
      </ul>
    </div>
  );
}

export function SharePage() {
  const { id = '' } = useParams();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['document', id], queryFn: () => api<{ document: DocumentDetail }>(`/api/documents/${id}`) });

  const [claimIds, setClaimIds] = useState<string[]>([]);
  const [includeFile, setIncludeFile] = useState(false);
  const [allowDownload, setAllowDownload] = useState(false);
  const [fileMode, setFileMode] = useState<'original' | 'redacted'>('original');
  const [redactions, setRedactions] = useState<Redaction[]>([]);
  const editor = useRef<RedactionEditorHandle>(null);
  const [recipientType, setRecipientType] = useState<'anyone' | 'organization'>('anyone');
  const [recipientLabel, setRecipientLabel] = useState('');
  const [org, setOrg] = useState<{ id: string; name: string } | null>(null);
  const [expiresIn, setExpiresIn] = useState<Expiry>('24h');
  const [customDate, setCustomDate] = useState('');
  const [restrictCountries, setRestrictCountries] = useState(true);
  const [countries, setCountries] = useState<string[]>(['SA']);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ url: string; expiresAt: string } | null>(null);
  const [watermark, setWatermark] = useState<WatermarkSettings>(DEFAULT_WATERMARK);
  const [preview, setPreview] = useState<{ status: 'idle' | 'loading' | 'ready' | 'error'; blob?: Blob; message?: string }>({ status: 'idle' });

  // What the owner chose to hide (at upload or on the document): applied to redacted copies.
  const plan = useQuery({
    queryKey: ['redaction-plan', id],
    queryFn: () => api<{ redactions: Redaction[] }>(`/api/documents/${id}/redaction-plan`),
    enabled: Boolean(id),
  });
  const savedPlan = plan.data?.redactions ?? [];
  const planApplied = useRef(false);
  useEffect(() => {
    // Including the file of a document with hidden information starts from a redacted copy.
    if (includeFile && savedPlan.length > 0 && !planApplied.current) {
      planApplied.current = true;
      setFileMode('redacted');
      setRedactions(savedPlan);
    }
  }, [includeFile, savedPlan]);

  // A preview shows one exact set of choices: any change makes it stale, so it is cleared.
  const previewKey = JSON.stringify([includeFile, fileMode, redactions, watermark, recipientType, recipientLabel, org?.id]);
  useEffect(() => {
    setPreview({ status: 'idle' });
  }, [previewKey]);

  if (isLoading || !data) return <Spinner />;
  const doc = data.document;
  const recipientName = recipientType === 'organization' ? (org?.name ?? '') : recipientLabel;

  /** The page renderings of a PDF for a redacted copy, checked against the size limit. */
  const pageForm = async (json: unknown) => {
    const form = new FormData();
    form.append('link', JSON.stringify(json));
    const pages = (await editor.current?.exportPages()) ?? [];
    const total = pages.reduce((sum, p) => sum + p.size, 0);
    if (total > REDACTION_MAX_TOTAL_BYTES) {
      throw new Error('This document has too many detailed pages for a redacted copy. Split it into smaller documents.');
    }
    pages.forEach((p, i) => form.append('page', p, `page-${i + 1}.jpg`));
    return form;
  };

  const showPreview = async () => {
    setPreview({ status: 'loading' });
    try {
      const redacted = fileMode === 'redacted';
      const json = { fileMode, redactions: redacted ? redactions : [], recipientLabel: recipientName, watermark, copy: 'view' };
      const blob = await apiPostBlob(`/api/documents/${doc.id}/links/preview`, redacted ? { form: await pageForm(json) } : { body: json });
      setPreview({ status: 'ready', blob });
    } catch (err) {
      const fields = err instanceof ApiError ? Object.values(err.fields) : [];
      setPreview({ status: 'error', message: fields[0] ?? errorMessage(err) });
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const redacted = includeFile && fileMode === 'redacted';
      const settings = {
        claimIds,
        includeFile,
        allowDownload: includeFile && allowDownload,
        fileMode: includeFile ? fileMode : 'original',
        redactions: redacted ? redactions : [],
        recipientType,
        recipientOrgId: recipientType === 'organization' ? org?.id : undefined,
        recipientLabel: recipientType === 'organization' ? (org?.name ?? '') : recipientLabel,
        expiresIn,
        expiresAt: expiresIn === 'custom' && customDate ? new Date(customDate).toISOString() : undefined,
        allowedCountries: restrictCountries ? countries : [],
        watermark,
      };
      let options: Parameters<typeof api>[1];
      if (redacted) {
        // The page renderings travel with the settings; the server burns the boxes in.
        options = { form: await pageForm(settings) };
      } else {
        options = { body: settings };
      }
      const res = await api<{ url: string; link: { expiresAt: string } }>(`/api/documents/${doc.id}/links`, options);
      setResult({ url: res.url, expiresAt: res.link.expiresAt });
      void queryClient.invalidateQueries({ queryKey: ['document', id] });
      void queryClient.invalidateQueries({ queryKey: ['links'] });
    } catch (err) {
      const fields = err instanceof ApiError ? Object.values(err.fields) : [];
      setError(fields[0] ?? errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  if (result) {
    const canShare = typeof navigator !== 'undefined' && 'share' in navigator;
    return (
      <div className="mx-auto max-w-xl">
        <Card className="overflow-hidden">
          <div className="hero-grid px-5 py-8 text-center text-white">
            <Seal size={104} draw className="text-accent drop-shadow-[0_0_20px_rgb(34_227_208/0.45)]" />
            <h1 className="mt-4 text-xl font-semibold">Your secure link is ready</h1>
            <p className="mt-1 text-sm text-navy-100">Send it to {recipientType === 'organization' ? org?.name : recipientLabel}. It stops working on {formatDateTime(result.expiresAt)}.</p>
          </div>
          <div className="space-y-4 p-5">
            <div className="rounded-xl bg-slate-50 p-3 font-mono text-xs break-all text-ink ring-1 ring-slate-200" data-testid="share-url">
              {result.url}
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <CopyButton value={result.url} label="Copy link" size="md" variant="primary" />
              {canShare ? (
                <Button
                  variant="secondary"
                  icon={<Send className="size-4" />}
                  onClick={() => navigator.share({ title: 'TrustPass secure document', text: `${doc.title} (shared securely with TrustPass)`, url: result.url }).catch(() => undefined)}
                >
                  Send…
                </Button>
              ) : (
                <a href={result.url} target="_blank" rel="noreferrer noopener" className="inline-flex h-11 items-center justify-center gap-2 rounded-xl text-sm font-medium text-ink ring-1 ring-slate-300 hover:bg-slate-50">
                  <ExternalLink className="size-4" /> Preview as recipient
                </a>
              )}
            </div>
            <ul className="space-y-1.5 text-sm text-slate-600">
              <li>• {claimIds.length} field{claimIds.length === 1 ? '' : 's'}{includeFile ? ' and the file' : ' only, not the file'}</li>
              {includeFile && <li>• {fileMode === 'redacted' ? `Redacted copy: ${redactions.length} area${redactions.length === 1 ? '' : 's'} hidden` : 'The original file'}</li>}
              {includeFile && <li>• {watermark.enabled ? `Watermark: ${WATERMARK_STYLE_LABELS[watermark.style].toLowerCase()}` : 'No watermark (views and downloads are still logged)'}</li>}
              {includeFile && <li>• {allowDownload ? 'Recipient can download a PDF copy' : 'View only: downloads are off'}</li>}
              <li>• {restrictCountries && countries.length ? `Only from ${countries.map(flag).join(' ')}` : 'No country restriction'}</li>
              <li>• You can revoke it at any time from Shared links</li>
            </ul>
            <div className="flex flex-col gap-2 sm:flex-row">
              <ButtonLink to="/app/links" variant="secondary" className="flex-1">
                Manage links
              </ButtonLink>
              <ButtonLink to={`/app/documents/${doc.id}`} variant="ghost" className="flex-1">
                Back to document
              </ButtonLink>
            </div>
          </div>
        </Card>
      </div>
    );
  }

  const toggleClaim = (cid: string) => setClaimIds((ids) => (ids.includes(cid) ? ids.filter((x) => x !== cid) : [...ids, cid]));

  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader
        back={
          <Link to={`/app/documents/${doc.id}`} className="mb-3 inline-flex items-center gap-1 text-sm font-medium text-accent">
            <ArrowLeft className="size-4" /> {doc.title}
          </Link>
        }
        title="Share document"
        description="Choose exactly what the recipient can see. Every rule below is enforced by the server, on every request."
      />
      <form onSubmit={submit} className="space-y-4">
        <Step n={1} title="What to share" icon={<ListChecks className="size-4" />}>
          {doc.claims.length > 0 ? (
            <ul className="space-y-2">
              {doc.claims.map((c) => (
                <li key={c.id}>
                  <label className={clsx('flex cursor-pointer items-center gap-3 rounded-xl p-3 ring-1 ring-inset transition-colors', claimIds.includes(c.id) ? 'bg-teal-50 ring-teal-300' : 'ring-slate-200 hover:bg-slate-50')}>
                    <input type="checkbox" checked={claimIds.includes(c.id)} onChange={() => toggleClaim(c.id)} className="size-5 rounded accent-teal-600" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm text-slate-500">{c.label}</span>
                      <span className="block truncate font-medium text-ink">{c.value}</span>
                    </span>
                    {c.source === 'issuer' ? <Badge tone="teal">Signed</Badge> : <Badge tone="amber">Self-declared</Badge>}
                  </label>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-slate-500">This document has no individual fields, so you can share the file only.</p>
          )}
          <div className="mt-4 rounded-xl bg-slate-50 p-3.5 ring-1 ring-slate-200">
            <Toggle
              checked={includeFile}
              onChange={setIncludeFile}
              label={
                <span className="flex items-center gap-1.5">
                  <FileText className="size-4" /> Include the file (view only)
                </span>
              }
              description="The file shows everything printed on it. Leave this off to share only the fields above."
            />
            {includeFile && (
              <div className="mt-3 border-t border-slate-200 pt-3" data-testid="allow-download">
                <Toggle
                  checked={allowDownload}
                  onChange={setAllowDownload}
                  label={
                    <span className="flex items-center gap-1.5">
                      <Download className="size-4" /> Allow download of a PDF copy
                    </span>
                  }
                  description="The recipient gets a separate PDF made for this download, never your stored original, which stays encrypted and unchanged. With the watermark on, their name, the time and a unique reference are on every page. Expiry, revocation and country rules are checked before every download."
                />
              </div>
            )}
          </div>
          {includeFile && (
            <div className="mt-3 space-y-3" data-testid="file-mode">
              <Segmented
                label="Which file"
                value={fileMode}
                onChange={(v) => {
                  setFileMode(v);
                  if (v === 'original') setRedactions([]);
                  else if (redactions.length === 0 && savedPlan.length > 0) setRedactions(savedPlan);
                }}
                options={[
                  { value: 'original', label: 'Original file' },
                  { value: 'redacted', label: 'Redacted copy' },
                ]}
              />
              {fileMode === 'original' && doc.claims.length > 0 && (
                <Alert tone="warning">Sharing the original file reveals everything printed on it, including fields you did not tick.</Alert>
              )}
              {fileMode === 'redacted' && (
                <>
                  <Alert tone="info">
                    The recipient gets a new copy made only of page images, with your hidden areas burned in. Nothing under them, and no
                    text, hidden layer or file information of the original, is in their copy. Your original stays encrypted and unchanged.
                  </Alert>
                  {savedPlan.length > 0 && (
                    <p className="text-[13px] text-slate-600" data-testid="plan-applied">
                      Starts from the information you chose to hide ({savedPlan.length} area{savedPlan.length === 1 ? '' : 's'}). Changes here apply to this link only.
                    </p>
                  )}
                  <RedactionEditor ref={editor} documentId={doc.id} mimeType={doc.mimeType} boxes={redactions} onChange={setRedactions} />
                </>
              )}
            </div>
          )}
        </Step>

        {includeFile && (
          <Step n={2} title="Watermark and preview" icon={<Stamp className="size-4" />}>
            <WatermarkControls value={watermark} onChange={setWatermark} recipient={recipientName} />
            <div className="mt-5 border-t border-slate-200 pt-4" data-testid="recipient-preview">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="max-w-md text-[13px] text-slate-500">
                  See exactly what the recipient will get: the server builds their copy with your choices above. Nothing is shared or saved.
                </p>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  loading={preview.status === 'loading'}
                  disabled={fileMode === 'redacted' && redactions.length === 0}
                  icon={preview.status === 'ready' ? <RefreshCw className="size-4" /> : <Eye className="size-4" />}
                  onClick={showPreview}
                >
                  {preview.status === 'ready' ? 'Refresh preview' : 'Preview recipient copy'}
                </Button>
              </div>
              {fileMode === 'redacted' && redactions.length === 0 && <p className="mt-2 text-[13px] text-slate-500">Mark at least one area to hide first.</p>}
              {preview.status === 'error' && (
                <Alert tone="error" className="mt-3">
                  {preview.message}
                </Alert>
              )}
              {preview.status === 'ready' && preview.blob && (
                <div className="mt-3 overflow-hidden rounded-xl ring-1 ring-slate-200">
                  <div className="flex items-center justify-between gap-2 bg-slate-50 px-3 py-2 text-[13px] text-slate-600">
                    <span>Recipient copy preview{fileMode === 'redacted' ? ': hidden areas are burned in' : ''}</span>
                    <button type="button" className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-slate-600 hover:bg-slate-100" onClick={() => setPreview({ status: 'idle' })}>
                      <X className="size-3.5" /> Close
                    </button>
                  </div>
                  <div className="max-h-[70vh] overflow-y-auto bg-slate-100/70 p-3" data-testid="preview-viewer">
                    <LazyPdfViewer src={preview.blob} label="Recipient copy preview" />
                  </div>
                </div>
              )}
            </div>
          </Step>
        )}

        <Step n={includeFile ? 3 : 2} title="Who can open it" icon={<Users className="size-4" />}>
          <Segmented
            label="Recipient type"
            value={recipientType}
            onChange={setRecipientType}
            options={[
              { value: 'anyone', label: 'Anyone with the link' },
              { value: 'organization', label: 'A TrustPass organization' },
            ]}
          />
          <div className="mt-4">
            {recipientType === 'anyone' ? (
              <Field label="Recipient name" htmlFor="recipient" hint={includeFile && watermark.enabled ? 'Shown to the recipient and printed in the watermark.' : 'Shown to the recipient.'}>
                <Input id="recipient" value={recipientLabel} onChange={(e) => setRecipientLabel(e.target.value)} placeholder="e.g. Example Company HR" maxLength={80} required />
              </Field>
            ) : (
              <>
                <OrgSearch value={org} onChange={setOrg} />
                <p className="mt-2 text-[13px] text-slate-500">Only signed-in members of this organization can open the link. Anyone else is refused, even with the link.</p>
              </>
            )}
          </div>
        </Step>

        <Step n={includeFile ? 4 : 3} title="How long it works" icon={<Clock className="size-4" />}>
          <Segmented
            label="Expiry"
            value={expiresIn}
            onChange={setExpiresIn}
            options={(['1h', '24h', '3d', '7d', 'custom'] as const).map((v) => ({ value: v, label: EXPIRY_LABELS[v] }))}
          />
          {expiresIn === 'custom' && (
            <div className="mt-3">
              <Input type="datetime-local" value={customDate} onChange={(e) => setCustomDate(e.target.value)} aria-label="Expiry date and time" required />
            </div>
          )}
          <p className="mt-3 text-[13px] text-slate-500">After this, the link stops working automatically. You can also revoke it earlier.</p>
        </Step>

        <Step n={includeFile ? 5 : 4} title="Where it can be opened" icon={<Globe2 className="size-4" />}>
          <Toggle checked={restrictCountries} onChange={setRestrictCountries} label="Restrict by country" description="Checked on the server from the visitor's IP address. Location is approximate: VPNs and mobile networks can change it." />
          {restrictCountries && (
            <div className="mt-4">
              <CountryPicker value={countries} onChange={setCountries} />
              {countries.length === 0 && <p className="mt-2 text-sm text-amber-700">Pick at least one country, or turn the restriction off.</p>}
            </div>
          )}
        </Step>

        {error && <Alert tone="error">{error}</Alert>}

        <Button
          type="submit"
          size="lg"
          variant="teal"
          className="w-full"
          loading={submitting}
          icon={<Share2 className="size-5" />}
          disabled={(claimIds.length === 0 && !includeFile) || (includeFile && fileMode === 'redacted' && redactions.length === 0) || (restrictCountries && countries.length === 0) || (recipientType === 'organization' && !org)}
        >
          Create secure link
        </Button>
      </form>
    </div>
  );
}

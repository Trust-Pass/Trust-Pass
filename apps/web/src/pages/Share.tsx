import { EXPIRY_LABELS } from '@trustpass/shared';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowLeft, Building2, CheckCircle2, Clock, ExternalLink, FileText, Globe2, ListChecks, Send, Share2, Users, Download } from 'lucide-react';
import { useState, type FormEvent, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { CountryPicker } from '../components/CountryPicker';
import { Alert, Badge, Button, ButtonLink, Card, CopyButton, Field, Input, PageHeader, Segmented, Spinner, Toggle } from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { flag, formatDateTime } from '../lib/format';
import type { DocumentDetail } from '../lib/types';

type Expiry = '1h' | '24h' | '3d' | '7d' | 'custom';

function Step({ n, title, icon, children }: { n: number; title: string; icon: ReactNode; children: ReactNode }) {
  return (
    <Card className="p-4 sm:p-5">
      <div className="mb-4 flex items-center gap-2.5">
        <span className="flex size-7 items-center justify-center rounded-full bg-gradient-to-br from-blue-400 to-blue-600 text-xs font-bold text-white shadow-glow">{n}</span>
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

  if (isLoading || !data) return <Spinner />;
  const doc = data.document;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await api<{ url: string; link: { expiresAt: string } }>(`/api/documents/${doc.id}/links`, {
        body: {
          claimIds,
          includeFile,
          allowDownload: includeFile && allowDownload,
          recipientType,
          recipientOrgId: recipientType === 'organization' ? org?.id : undefined,
          recipientLabel: recipientType === 'organization' ? (org?.name ?? '') : recipientLabel,
          expiresIn,
          expiresAt: expiresIn === 'custom' && customDate ? new Date(customDate).toISOString() : undefined,
          allowedCountries: restrictCountries ? countries : [],
        },
      });
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
            <CheckCircle2 className="mx-auto size-12 text-teal-400" />
            <h1 className="mt-3 text-xl font-bold">Your secure link is ready</h1>
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
              <li>• {claimIds.length} field{claimIds.length === 1 ? '' : 's'}{includeFile ? ' and the watermarked file' : ' only, not the file'}</li>
              {includeFile && <li>• {allowDownload ? 'Recipient can download a watermarked PDF copy' : 'View only: downloads are off'}</li>}
              <li>• {restrictCountries && countries.length ? `Only from ${countries.map(flag).join(' ')}` : 'No country restriction'}</li>
              <li>• You can revoke it at any time from Sharing links</li>
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
        title="Share securely"
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
                  <FileText className="size-4" /> Include the file (view only, watermarked)
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
                      <Download className="size-4" /> Allow download of a watermarked PDF
                    </span>
                  }
                  description="The recipient gets a separate copy with their name, the time and a unique reference on every page. Your original stays encrypted and unchanged. Expiry, revocation and country rules are checked before every download."
                />
              </div>
            )}
          </div>
          {includeFile && doc.claims.length > 0 && (
            <Alert tone="warning" className="mt-3">
              Sharing the file reveals every field on it, including those you did not tick.
            </Alert>
          )}
        </Step>

        <Step n={2} title="Who can open it" icon={<Users className="size-4" />}>
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
              <Field label="Recipient name" htmlFor="recipient" hint="Shown to the recipient and burned into the watermark.">
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

        <Step n={3} title="How long it works" icon={<Clock className="size-4" />}>
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

        <Step n={4} title="Where it can be opened" icon={<Globe2 className="size-4" />}>
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
          disabled={(claimIds.length === 0 && !includeFile) || (restrictCountries && countries.length === 0) || (recipientType === 'organization' && !org)}
        >
          Create secure link
        </Button>
      </form>
    </div>
  );
}

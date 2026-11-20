import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, ChevronDown, Clock, Download, Globe2, Link2, Pencil, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { CountryPicker } from '../components/CountryPicker';
import {
  Button,
  ButtonLink,
  Card,
  ConfirmModal,
  CopyButton,
  EmptyState,
  LinkStatusBadge,
  Modal,
  OutcomeBadge,
  PageHeader,
  Spinner,
  Tabs,
} from '../components/ui';
import { api, errorMessage } from '../lib/api';
import { country, flag, formatDateTime, relativeTime } from '../lib/format';
import type { AccessOutcome, LinkSummary } from '../lib/types';

interface LinkDetail {
  link: LinkSummary & {
    fields: Array<{ id: string; label: string; source: string }>;
    viewCount: number;
    recentAccess: Array<{ id: string; outcome: AccessOutcome; resource: string; country: string | null; client: string | null; at: string }>;
  };
}

function LinkActivity({ id }: { id: string }) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['link', id], queryFn: () => api<LinkDetail>(`/api/links/${id}`) });
  const setDownload = useMutation({
    mutationFn: (allowDownload: boolean) => api(`/api/links/${id}/download`, { method: 'PUT', body: { allowDownload } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['link', id] });
      void queryClient.invalidateQueries({ queryKey: ['links'] });
    },
  });
  if (isLoading || !data) return <Spinner />;
  const l = data.link;
  return (
    <div className="space-y-3 border-t border-slate-100 px-4 py-4 sm:px-5">
      <p className="text-sm text-slate-600">
        <span className="font-medium text-ink">Shared:</span> {l.fields.map((f) => f.label).join(', ') || 'no fields'}
        {l.includeFile && (l.fileMode === 'redacted' ? ' + redacted copy' : ' + watermarked file')}
      </p>
      {l.includeFile && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-slate-50 px-3 py-2.5 text-sm ring-1 ring-slate-200" data-testid="link-download">
          <span className="flex items-center gap-1.5 text-ink">
            <Download className="size-4" /> {l.allowDownload ? 'Recipient can download a watermarked PDF' : 'View only: downloads are off'}
          </span>
          {l.status === 'active' && (
            <Button variant="secondary" size="sm" loading={setDownload.isPending} onClick={() => setDownload.mutate(!l.allowDownload)}>
              {l.allowDownload ? 'Turn off downloads' : 'Allow downloads'}
            </Button>
          )}
          {setDownload.error && <p className="w-full text-[13px] text-red-500">{errorMessage(setDownload.error)}</p>}
        </div>
      )}
      {l.recentAccess.length === 0 ? (
        <p className="text-sm text-slate-500">No access attempts yet.</p>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-xl ring-1 ring-slate-200">
          {l.recentAccess.map((a) => (
            <li key={a.id} className="flex items-center justify-between gap-2 px-3 py-2.5 text-sm">
              <span className="min-w-0">
                <span className="block text-ink">{country(a.country)}</span>
                <span className="block truncate text-xs text-slate-500">
                  {a.client} · {a.resource === 'download' ? 'download' : a.resource === 'file' ? 'file' : 'details'} · {formatDateTime(a.at)}
                </span>
              </span>
              <OutcomeBadge outcome={a.outcome} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function LinksPage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<'active' | 'expired' | 'revoked' | 'all'>('active');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<LinkSummary | null>(null);
  const [editing, setEditing] = useState<LinkSummary | null>(null);
  const [countries, setCountries] = useState<string[]>([]);

  const { data, isLoading } = useQuery({ queryKey: ['links', 'all'], queryFn: () => api<{ links: LinkSummary[] }>('/api/links?status=all') });
  const links = data?.links ?? [];
  const shown = links.filter((l) => status === 'all' || l.status === status);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['links'] });
    void queryClient.invalidateQueries({ queryKey: ['link'] });
  };

  const revoke = useMutation({
    mutationFn: (id: string) => api(`/api/links/${id}/revoke`, { method: 'POST' }),
    onSuccess: () => {
      setRevoking(null);
      refresh();
    },
  });
  const saveCountries = useMutation({
    mutationFn: ({ id, codes }: { id: string; codes: string[] }) => api(`/api/links/${id}/countries`, { method: 'PUT', body: { allowedCountries: codes } }),
    onSuccess: () => {
      setEditing(null);
      refresh();
    },
  });

  return (
    <div>
      <PageHeader
        title="Sharing links"
        description="Every link you created, who it is for, what it reveals and what happened to it. Changes apply on the very next request."
        actions={<ButtonLink to="/app/documents">Share a document</ButtonLink>}
      />
      <div className="mb-4">
        <Tabs
          value={status}
          onChange={setStatus}
          tabs={[
            { value: 'active', label: 'Active', count: links.filter((l) => l.status === 'active').length },
            { value: 'expired', label: 'Expired', count: links.filter((l) => l.status === 'expired').length },
            { value: 'revoked', label: 'Revoked', count: links.filter((l) => l.status === 'revoked').length },
            { value: 'all', label: 'All', count: links.length },
          ]}
        />
      </div>

      {isLoading ? (
        <Spinner />
      ) : shown.length === 0 ? (
        <Card>
          <EmptyState icon={<Link2 className="size-6" />} title="No links here" body="Open a document and choose Share securely to create one." />
        </Card>
      ) : (
        <ul className="space-y-3">
          {shown.map((l) => (
            <li key={l.id}>
              <Card className="overflow-hidden">
                <div className="p-4 sm:p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <Link to={`/app/documents/${l.document.id}`} className="line-clamp-1 font-semibold text-ink hover:underline">
                        {l.document.title}
                      </Link>
                      <p className="mt-0.5 text-sm text-slate-600">
                        For <span className="font-medium text-ink">{l.recipientOrg ?? l.recipientLabel}</span>
                        {l.recipientType === 'organization' && ' (members only)'}
                      </p>
                    </div>
                    <LinkStatusBadge status={l.status} />
                  </div>
                  <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[13px] text-slate-600">
                    <span className="flex items-center gap-1">
                      <ShieldCheck className="size-3.5" /> {l.claimCount} field{l.claimCount === 1 ? '' : 's'}
                      {l.includeFile && (l.fileMode === 'redacted' ? ' + redacted copy' : ' + file')}
                      {l.includeFile && l.allowDownload && ' (download allowed)'}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="size-3.5" /> {l.status === 'active' ? `Expires ${relativeTime(l.expiresAt)}` : l.revokedAt ? `Revoked ${relativeTime(l.revokedAt)}` : `Expired ${relativeTime(l.expiresAt)}`}
                    </span>
                    <span className="flex items-center gap-1">
                      <Globe2 className="size-3.5" /> {l.countries.length ? l.countries.map(flag).join(' ') : 'Any country'}
                    </span>
                    <span>
                      {l.attempts.granted} views · <span className={l.attempts.denied ? 'font-medium text-red-400' : ''}>{l.attempts.denied} blocked</span>
                    </span>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {l.status === 'active' && (
                      <>
                        <CopyLink id={l.id} />
                        <Button
                          size="sm"
                          variant="secondary"
                          icon={<Pencil className="size-4" />}
                          onClick={() => {
                            setCountries(l.countries);
                            setEditing(l);
                          }}
                        >
                          Countries
                        </Button>
                        <Button size="sm" variant="secondary" className="text-red-400" icon={<Ban className="size-4" />} onClick={() => setRevoking(l)}>
                          Revoke
                        </Button>
                      </>
                    )}
                    <Button size="sm" variant="ghost" icon={<ChevronDown className={expanded === l.id ? 'size-4 rotate-180' : 'size-4'} />} onClick={() => setExpanded(expanded === l.id ? null : l.id)}>
                      Activity
                    </Button>
                  </div>
                </div>
                {expanded === l.id && <LinkActivity id={l.id} />}
              </Card>
            </li>
          ))}
        </ul>
      )}

      <ConfirmModal
        open={Boolean(revoking)}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
        loading={revoke.isPending}
        title="Revoke this link?"
        confirmLabel="Revoke now"
        body={
          <>
            <p>
              {revoking?.recipientOrg ?? revoking?.recipientLabel} will no longer be able to open "{revoking?.document.title}". This takes effect on the next request and cannot be undone.
            </p>
            {revoke.error && <p className="mt-2 text-red-400">{errorMessage(revoke.error)}</p>}
          </>
        }
      />

      <Modal
        open={Boolean(editing)}
        onClose={() => setEditing(null)}
        title="Allowed countries"
        footer={
          <>
            <Button variant="secondary" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button loading={saveCountries.isPending} onClick={() => editing && saveCountries.mutate({ id: editing.id, codes: countries })}>
              Save
            </Button>
          </>
        }
      >
        <p className="mb-4 text-sm text-slate-600">Leave empty to allow any country. Location is approximate (IP-based).</p>
        <CountryPicker value={countries} onChange={setCountries} />
        {saveCountries.error && <p className="mt-3 text-sm text-red-400">{errorMessage(saveCountries.error)}</p>}
      </Modal>
    </div>
  );
}

function CopyLink({ id }: { id: string }) {
  const { data } = useQuery({ queryKey: ['link-url', id], queryFn: () => api<{ url: string }>(`/api/links/${id}/url`), staleTime: Infinity });
  if (!data) return <Button size="sm" variant="secondary" loading>Copy link</Button>;
  return <CopyButton value={data.url} label="Copy link" />;
}

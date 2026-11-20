import { SECURITY_EVENT_LABELS } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { GraduationCap, KeyRound, QrCode, Share2, Upload } from 'lucide-react';
import { Link } from 'react-router';
import { AccessChart, type DayPoint } from '../components/AccessChart';
import { Seal } from '../components/Seal';
import { ButtonLink, Card, CardHeader, EmptyState, Spinner } from '../components/ui';
import { api } from '../lib/api';
import { useMe } from '../lib/auth';
import { relativeTime } from '../lib/format';
import type { AccessOutcome } from '../lib/types';

interface DashboardData {
  counts: { documents: number; verifiedCredentials: number; activeLinks: number; attempts7d: number; granted7d: number; denied7d: number };
  daily?: DayPoint[];
  protection?: { keyProvider: string; kms: boolean };
  recentAccess: Array<{ id: string; at: string; outcome: AccessOutcome; country: string | null; document: string; recipient: string | null }>;
  recentEvents: Array<{ id: string; type: string; severity: string; at: string }>;
}

function greeting(date = new Date()) {
  const h = date.getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

function Metric({ label, value, note, tone = 'calm' }: { label: string; value: number; note: string; tone?: 'calm' | 'alert' }) {
  return (
    <div className="min-w-0 border-accent/10 sm:border-l sm:pl-5 sm:first:border-l-0 sm:first:pl-0">
      <p className="text-[12.5px] text-slate-500">{label}</p>
      <p className={clsx('num mt-1.5 text-[32px] leading-none font-semibold', tone === 'alert' && value > 0 ? 'text-red-700' : 'text-ink')}>{value}</p>
      <p className={clsx('mt-2 text-xs', tone === 'alert' && value > 0 ? 'text-red-700' : 'text-glow')}>{note}</p>
    </div>
  );
}

export function DashboardPage() {
  const me = useMe();
  const { data, isLoading } = useQuery({ queryKey: ['dashboard'], queryFn: () => api<DashboardData>('/api/dashboard') });
  const firstName = me.user.fullName.split(' ')[0];

  if (isLoading || !data) return <Spinner />;
  const { counts } = data;
  const onboarding = counts.documents === 0;
  const kms = data.protection?.kms ?? false;
  const summary = onboarding
    ? 'Your vault is ready. Add your first document to start sharing safely.'
    : `${counts.documents} ${counts.documents === 1 ? 'document is' : 'documents are'} sealed. ${counts.activeLinks} ${counts.activeLinks === 1 ? 'link is' : 'links are'} live${counts.denied7d > 0 ? `, and ${counts.denied7d} ${counts.denied7d === 1 ? 'attempt was' : 'attempts were'} blocked this week` : ''}.`;

  return (
    <div className="space-y-5 sm:space-y-6">
      <div className="flex animate-rise flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-[28px] leading-tight font-semibold text-ink sm:text-[32px]">
            {greeting()}, {firstName}
          </h1>
          <p className="mt-1.5 max-w-xl text-[15px] text-slate-500">{summary}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <ButtonLink to="/app/scan" variant="secondary" icon={<QrCode className="size-4" />}>
            Scan a QR code
          </ButtonLink>
          <ButtonLink to="/app/documents/upload" icon={<Upload className="size-4" />}>
            Upload document
          </ButtonLink>
        </div>
      </div>

      {/* The vault: the one lit card on the page. */}
      <Card as="section" className="card-lit overflow-hidden">
        <div className="grid gap-6 p-5 sm:p-7 lg:grid-cols-[auto_1fr] lg:items-center lg:gap-9">
          <div className="hidden lg:block">
            <Seal size={140} className="text-accent drop-shadow-[0_0_22px_rgb(34_227_208/0.35)]" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="text-[12.5px] text-slate-500">Vault integrity</p>
                <h2 className="mt-1 text-[20px] font-semibold text-ink sm:text-[22px]">
                  {onboarding ? 'Your vault is empty and ready' : `All ${counts.documents} ${counts.documents === 1 ? 'document' : 'documents'} encrypted`}
                </h2>
              </div>
            <div className="sm:text-right" data-testid="key-protection">
              <span className={clsx('inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset', kms ? 'bg-teal-50 text-teal-800 ring-teal-200' : 'bg-amber-50 text-amber-800 ring-amber-200')}>
                <KeyRound className="size-3.5" aria-hidden /> {kms ? 'Keys protected by Google Cloud KMS' : 'Keys protected by the server master key'}
              </span>
              {!kms && <p className="mt-2 max-w-64 text-xs text-slate-500 sm:ml-auto">Google Cloud KMS is not active yet. Files are still encrypted with AES-256-GCM.</p>}
            </div>
            </div>
            <div className="mt-5 grid grid-cols-2 gap-y-5 sm:grid-cols-4">
              <Metric label="Documents" value={counts.documents} note="AES-256-GCM, own key" />
              <Metric label="Live links" value={counts.activeLinks} note="working right now" />
              <Metric label="Views, 7 days" value={counts.granted7d} note={`${counts.verifiedCredentials} signed credential${counts.verifiedCredentials === 1 ? '' : 's'}`} />
              <Metric label="Blocked, 7 days" value={counts.denied7d} note={counts.denied7d > 0 ? 'see security activity' : 'nothing blocked'} tone="alert" />
            </div>
          </div>
        </div>
      </Card>

      {onboarding && (
        <Card className="p-5 sm:p-6">
          <h2 className="text-lg font-semibold text-ink">Try the full TrustPass flow in 2 minutes</h2>
          <p className="mt-1 text-sm text-slate-500">Works best with a second phone or a friend nearby.</p>
          <ol className="mt-4 space-y-3 text-sm">
            {[
              ['Get a signed demo credential', '/app/credentials', 'Demo University issues you an enrollment certificate with an Ed25519 signature.'],
              ['Share only your enrollment status', '/app/documents', 'Pick one field, an expiry and allowed countries.'],
              ['Open the link on another device', '/app/links', 'Then revoke it and watch it stop working, live.'],
            ].map(([title, to, body], i) => (
              <li key={title} className="flex gap-3">
                <span className="num flex size-6 shrink-0 items-center justify-center rounded-full bg-accent/15 text-xs font-semibold text-accent ring-1 ring-accent/40">{i + 1}</span>
                <span>
                  <Link to={to!} className="font-semibold text-ink underline decoration-accent/50 underline-offset-4 hover:decoration-accent">
                    {title}
                  </Link>
                  <span className="block text-slate-500">{body}</span>
                </span>
              </li>
            ))}
          </ol>
          <ButtonLink to="/app/credentials" variant="secondary" className="mt-5" icon={<GraduationCap className="size-4" />}>
            Get a demo credential
          </ButtonLink>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1.55fr_1fr]">
        <Card className="p-4 sm:p-6">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[15px] font-semibold text-ink">Who opened your links</h2>
            <div className="flex items-center gap-4 text-xs text-slate-500">
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2 rounded-full bg-accent shadow-[0_0_8px_rgb(34_227_208/0.8)]" aria-hidden /> Viewed
              </span>
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2 rounded-sm bg-[#f43f5e]" aria-hidden /> Blocked
              </span>
              <span>14 days</span>
            </div>
          </div>
          {data.daily && data.daily.some((d) => d.granted + d.denied > 0) ? (
            <AccessChart days={data.daily} />
          ) : (
            <EmptyState icon={<Share2 className="size-6" />} title="No views yet" body="When someone opens one of your links, the last 14 days appear here." />
          )}
        </Card>

        <Card>
          <CardHeader title="Security activity" action={<Link to="/app/activity" className="text-sm font-medium text-accent hover:underline">View all</Link>} />
          <ol className="relative px-5 py-4">
            <span className="absolute top-6 bottom-6 left-[27px] w-px bg-gradient-to-b from-accent/30 to-transparent" aria-hidden />
            {data.recentEvents.map((e) => (
              <li key={e.id} className="relative flex gap-3 pb-4 last:pb-0">
                <span
                  className={clsx(
                    'relative mt-1 size-2.5 shrink-0 rounded-full border-2 bg-surface',
                    e.severity === 'high' ? 'border-red-500' : e.severity === 'info' ? 'border-accent' : 'border-amber-400',
                  )}
                  aria-hidden
                />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-ink">{SECURITY_EVENT_LABELS[e.type] ?? e.type}</p>
                  <p className="text-xs text-slate-500">
                    {relativeTime(e.at)}
                    {e.severity !== 'info' && <span className={e.severity === 'high' ? 'text-red-700' : 'text-amber-700'}> · {e.severity === 'high' ? 'Important' : 'Review'}</span>}
                  </p>
                </div>
              </li>
            ))}
          </ol>
        </Card>
      </div>

    </div>
  );
}

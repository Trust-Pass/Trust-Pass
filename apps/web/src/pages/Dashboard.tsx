import { SECURITY_EVENT_LABELS } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import { Activity, BadgeCheck, FileText, GraduationCap, Link2, Share2, ShieldAlert, Upload } from 'lucide-react';
import { Link } from 'react-router';
import { Badge, ButtonLink, Card, CardHeader, EmptyState, OutcomeBadge, Spinner, StatCard } from '../components/ui';
import { api } from '../lib/api';
import { useMe } from '../lib/auth';
import { country, relativeTime } from '../lib/format';
import type { AccessOutcome } from '../lib/types';
import { Seal } from '../components/Seal';

interface DashboardData {
  counts: { documents: number; verifiedCredentials: number; activeLinks: number; attempts7d: number; granted7d: number; denied7d: number };
  recentAccess: Array<{ id: string; at: string; outcome: AccessOutcome; country: string | null; document: string; recipient: string | null }>;
  recentEvents: Array<{ id: string; type: string; severity: string; at: string }>;
}

export function DashboardPage() {
  const me = useMe();
  const { data, isLoading } = useQuery({ queryKey: ['dashboard'], queryFn: () => api<DashboardData>('/api/dashboard') });
  const firstName = me.user.fullName.split(' ')[0];

  if (isLoading || !data) return <Spinner />;
  const { counts } = data;
  const onboarding = counts.documents === 0;

  return (
    <div className="space-y-6">
      <div className="hero-grid relative flex animate-rise flex-col gap-5 overflow-hidden rounded-3xl px-5 py-7 shadow-lift sm:flex-row sm:items-end sm:justify-between sm:px-8 sm:py-9">
        <Seal size={260} emblem={false} className="pointer-events-none absolute -top-16 -right-14 text-navy-200 opacity-30" />
        <div className="relative">
          <h1 className="text-[28px] leading-tight font-semibold text-white sm:text-[34px]">Hello, {firstName}</h1>
          <p className="mt-1.5 text-[15px] text-navy-100">Here is what happened with your documents.</p>
        </div>
        <div className="relative flex flex-wrap gap-2">
          <ButtonLink to="/app/documents/upload" variant="secondary" icon={<Upload className="size-4" />}>
            Upload
          </ButtonLink>
          <ButtonLink to="/app/credentials" variant="band" icon={<GraduationCap className="size-4" />}>
            Demo credential
          </ButtonLink>
        </div>
      </div>

      {onboarding && (
        <Card className="overflow-hidden">
          <div className="px-5 py-6 sm:px-6">
            <h2 className="text-lg font-semibold text-ink">Try the full TrustPass flow in 2 minutes</h2>
            <p className="mt-1 text-sm text-slate-600">Works best with a second phone or a friend nearby.</p>
            <ol className="mt-4 space-y-3 text-sm">
              {[
                ['Get a signed demo credential', '/app/credentials', 'Demo University issues you an enrollment certificate with an Ed25519 signature.'],
                ['Share only your enrollment status', '/app/documents', 'Pick one field, an expiry and allowed countries.'],
                ['Open the link on another device', '/app/links', 'Then revoke it and watch it stop working, live.'],
              ].map(([title, to, body], i) => (
                <li key={title} className="flex gap-3">
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-accent text-xs font-semibold text-white tabular-nums">{i + 1}</span>
                  <span>
                    <Link to={to!} className="font-semibold text-ink underline decoration-accent-line underline-offset-4 hover:decoration-accent">
                      {title}
                    </Link>
                    <span className="block text-slate-600">{body}</span>
                  </span>
                </li>
              ))}
            </ol>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Documents" value={counts.documents} icon={<FileText className="size-4" />} hint="encrypted with AES-256-GCM" />
        <StatCard label="Verified credentials" value={counts.verifiedCredentials} icon={<BadgeCheck className="size-4" />} tone="teal" hint="issuer-signed" />
        <StatCard label="Active links" value={counts.activeLinks} icon={<Link2 className="size-4" />} hint="currently working" />
        <StatCard
          label="Access attempts (7 days)"
          value={counts.attempts7d}
          icon={<ShieldAlert className="size-4" />}
          tone={counts.denied7d > 0 ? 'amber' : 'slate'}
          hint={`${counts.granted7d} granted · ${counts.denied7d} blocked`}
        />
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title="Recent views of your links" icon={<Share2 className="size-5" />} action={<Link to="/app/analytics" className="text-sm font-medium text-accent hover:underline">Analytics</Link>} />
          {data.recentAccess.length === 0 ? (
            <EmptyState icon={<Share2 className="size-6" />} title="No views yet" body="When someone opens one of your links, it shows up here." />
          ) : (
            <ul className="divide-y divide-slate-100">
              {data.recentAccess.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-3 px-4 py-3 sm:px-5">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-ink">{a.document}</p>
                    <p className="truncate text-xs text-slate-500">
                      {a.recipient} · {country(a.country)} · {relativeTime(a.at)}
                    </p>
                  </div>
                  <OutcomeBadge outcome={a.outcome} />
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="Security activity" icon={<Activity className="size-5" />} action={<Link to="/app/activity" className="text-sm font-medium text-accent hover:underline">View all</Link>} />
          <ul className="divide-y divide-slate-100">
            {data.recentEvents.map((e) => (
              <li key={e.id} className="flex items-center justify-between gap-3 px-4 py-3 sm:px-5">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-ink">{SECURITY_EVENT_LABELS[e.type] ?? e.type}</p>
                  <p className="text-xs text-slate-500">{relativeTime(e.at)}</p>
                </div>
                {e.severity !== 'info' && <Badge tone={e.severity === 'high' ? 'red' : 'amber'}>{e.severity === 'high' ? 'Important' : 'Review'}</Badge>}
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}

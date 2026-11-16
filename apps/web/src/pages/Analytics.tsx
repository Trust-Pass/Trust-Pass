import { ACCESS_OUTCOMES } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Ban, CheckCircle2, Clock, Globe2, Link2, MapPin, ShieldAlert, Users } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Badge, Button, Card, CardHeader, EmptyState, Input, OUTCOME_UI, OutcomeBadge, PageHeader, Segmented, Select, Spinner, StatCard } from '../components/ui';
import { api } from '../lib/api';
import { country, formatDateTime, relativeTime } from '../lib/format';
import type { AccessOutcome, DocumentSummary } from '../lib/types';

interface AnalyticsData {
  range: { from: string; to: string };
  summary: {
    totalAttempts: number;
    granted: number;
    denied: number;
    expiredAttempts: number;
    revokedAttempts: number;
    countryBlocked: number;
    recipientBlocked: number;
    countriesDetected: number;
    distinctVisitors: number;
    lastAccess: { at: string; country: string | null } | null;
    activeLinks: number;
    expiredLinks: number;
    revokedLinks: number;
  };
  byCountry: Array<{ country: string | null; granted: number; denied: number }>;
  byDocument: Array<{ documentId: string; title: string; granted: number; denied: number }>;
  daily: Array<{ day: string; granted: number; denied: number }>;
  alerts: Array<{ id: string; type: string; title: string; body: string; at: string }>;
}

interface LogPage {
  page: number;
  pageSize: number;
  total: number;
  rows: Array<{ id: string; at: string; document: string; recipient: string | null; resource: string; outcome: AccessOutcome; country: string | null; client: string | null; organization: string | null }>;
}

const iso = (d: Date) => d.toISOString().slice(0, 10);

export function AnalyticsPage() {
  const [range, setRange] = useState<'7' | '30' | '90' | 'custom'>('30');
  const [custom, setCustom] = useState({ from: iso(new Date(Date.now() - 30 * 864e5)), to: iso(new Date()) });
  const [documentId, setDocumentId] = useState('');
  const [outcome, setOutcome] = useState('');
  const [page, setPage] = useState(1);

  const params = useMemo(() => {
    const p = new URLSearchParams();
    if (range === 'custom') {
      p.set('from', custom.from);
      p.set('to', custom.to);
    } else {
      p.set('from', iso(new Date(Date.now() - (Number(range) - 1) * 864e5)));
      p.set('to', iso(new Date()));
    }
    if (documentId) p.set('documentId', documentId);
    return p;
  }, [range, custom, documentId]);

  const docs = useQuery({ queryKey: ['documents'], queryFn: () => api<{ documents: DocumentSummary[] }>('/api/documents') });
  const { data, isLoading } = useQuery({ queryKey: ['analytics', params.toString()], queryFn: () => api<AnalyticsData>(`/api/analytics?${params}`) });
  const logParams = new URLSearchParams(params);
  if (outcome) logParams.set('outcome', outcome);
  logParams.set('page', String(page));
  const log = useQuery({ queryKey: ['access-log', logParams.toString()], queryFn: () => api<LogPage>(`/api/analytics/access-log?${logParams}`) });

  const chartData = data?.daily.map((d) => ({ ...d, label: d.day.slice(5) })) ?? [];
  const maxCountry = Math.max(1, ...(data?.byCountry.map((c) => c.granted + c.denied) ?? [1]));
  const s = data?.summary;

  return (
    <div className="space-y-5">
      <PageHeader title="Access analytics" description="What happened after you shared. Every number comes from a recorded access attempt." />

      <Card className="space-y-3 p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <Segmented
            label="Date range"
            value={range}
            onChange={(v) => {
              setRange(v);
              setPage(1);
            }}
            options={[
              { value: '7', label: '7 days' },
              { value: '30', label: '30 days' },
              { value: '90', label: '90 days' },
              { value: 'custom', label: 'Custom' },
            ]}
          />
          <Select
            aria-label="Document"
            value={documentId}
            onChange={(e) => {
              setDocumentId(e.target.value);
              setPage(1);
            }}
            className="lg:max-w-xs"
          >
            <option value="">All documents</option>
            {docs.data?.documents.map((d) => (
              <option key={d.id} value={d.id}>
                {d.title}
              </option>
            ))}
          </Select>
        </div>
        {range === 'custom' && (
          <div className="grid grid-cols-2 gap-2 sm:max-w-md">
            <Input type="date" aria-label="From" value={custom.from} onChange={(e) => setCustom((c) => ({ ...c, from: e.target.value }))} />
            <Input type="date" aria-label="To" value={custom.to} onChange={(e) => setCustom((c) => ({ ...c, to: e.target.value }))} />
          </div>
        )}
      </Card>

      {isLoading || !s ? (
        <Spinner />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="analytics-summary">
            <StatCard label="Total attempts" value={s.totalAttempts} icon={<Users className="size-4" />} hint={`${s.distinctVisitors} distinct visitors`} />
            <StatCard label="Granted" value={s.granted} icon={<CheckCircle2 className="size-4" />} tone="teal" />
            <StatCard label="Denied" value={s.denied} icon={<Ban className="size-4" />} tone={s.denied ? 'red' : 'slate'} hint={`${s.countryBlocked} by country · ${s.recipientBlocked} by recipient`} />
            <StatCard label="Expired-link attempts" value={s.expiredAttempts} icon={<Clock className="size-4" />} tone="slate" hint={`${s.revokedAttempts} on revoked links`} />
            <StatCard label="Countries detected" value={s.countriesDetected} icon={<Globe2 className="size-4" />} hint="approximate, IP-based" />
            <StatCard label="Last access" value={s.lastAccess ? relativeTime(s.lastAccess.at) : '—'} icon={<MapPin className="size-4" />} hint={s.lastAccess ? country(s.lastAccess.country) : 'no views yet'} />
            <StatCard label="Active links" value={s.activeLinks} icon={<Link2 className="size-4" />} tone="teal" />
            <StatCard label="Revoked links" value={s.revokedLinks} icon={<ShieldAlert className="size-4" />} tone="slate" hint={`${s.expiredLinks} expired`} />
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <Card>
              <CardHeader title="Attempts per day" subtitle={`${data.range.from} to ${data.range.to}`} />
              <div className="h-64 px-2 py-4">
                {s.totalAttempts === 0 ? (
                  <EmptyState icon={<Users className="size-6" />} title="No attempts in this period" />
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} margin={{ left: -20, right: 8 }}>
                      <CartesianGrid vertical={false} stroke="#e2e8f0" />
                      <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
                      <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} axisLine={false} />
                      <Tooltip cursor={{ fill: '#f1f5f9' }} />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Bar dataKey="granted" name="Granted" stackId="a" fill="#14b8a6" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="denied" name="Denied" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </Card>
            <Card>
              <CardHeader title="Approximate countries" subtitle="From the visitor's IP address; VPNs can change it." />
              {data.byCountry.length === 0 ? (
                <p className="px-5 py-6 text-sm text-slate-500">No location data yet.</p>
              ) : (
                <ul className="space-y-3 px-4 py-4 sm:px-5" data-testid="country-breakdown">
                  {data.byCountry.map((c) => (
                    <li key={c.country ?? 'unknown'}>
                      <div className="flex justify-between text-sm">
                        <span className="font-medium text-navy-950">{country(c.country)}</span>
                        <span className="text-slate-500">
                          {c.granted} granted · {c.denied} denied
                        </span>
                      </div>
                      <div className="mt-1.5 flex h-2 overflow-hidden rounded-full bg-slate-100">
                        <div className="bg-teal-500" style={{ width: `${(c.granted / maxCountry) * 100}%` }} />
                        <div className="bg-red-500" style={{ width: `${(c.denied / maxCountry) * 100}%` }} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <Card>
              <CardHeader title="By document" />
              {data.byDocument.length === 0 ? (
                <p className="px-5 py-6 text-sm text-slate-500">No attempts yet.</p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {data.byDocument.map((d) => (
                    <li key={d.documentId} className="flex items-center justify-between gap-3 px-4 py-3 sm:px-5">
                      <button type="button" onClick={() => setDocumentId(d.documentId)} className="min-w-0 truncate text-left text-sm font-medium text-navy-950 hover:underline">
                        {d.title}
                      </button>
                      <span className="shrink-0 text-sm text-slate-600">
                        <span className="text-teal-700">{d.granted}</span> / <span className="text-red-600">{d.denied}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card>
              <CardHeader title="Security alerts" subtitle="Worth a look, not proof of an attack." icon={<AlertTriangle className="size-5" />} />
              {data.alerts.length === 0 ? (
                <p className="px-5 py-6 text-sm text-slate-500">Nothing unusual in this period.</p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {data.alerts.map((a) => (
                    <li key={a.id} className="px-4 py-3 sm:px-5">
                      <p className="text-sm font-semibold text-navy-950">{a.title}</p>
                      <p className="mt-0.5 text-sm text-slate-600">{a.body}</p>
                      <p className="mt-1 text-xs text-slate-400">{relativeTime(a.at)}</p>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </>
      )}

      <Card>
        <CardHeader
          title="Access history"
          action={
            <Select
              aria-label="Outcome filter"
              value={outcome}
              onChange={(e) => {
                setOutcome(e.target.value);
                setPage(1);
              }}
              className="h-9 max-w-[11rem] py-1.5 text-sm"
            >
              <option value="">All outcomes</option>
              {ACCESS_OUTCOMES.map((o) => (
                <option key={o} value={o}>
                  {OUTCOME_UI[o].label}
                </option>
              ))}
            </Select>
          }
        />
        {log.isLoading || !log.data ? (
          <Spinner />
        ) : log.data.rows.length === 0 ? (
          <p className="px-5 py-6 text-sm text-slate-500">No matching attempts.</p>
        ) : (
          <>
            <ul className="divide-y divide-slate-100 md:hidden">
              {log.data.rows.map((r) => (
                <li key={r.id} className="px-4 py-3">
                  <div className="flex items-start justify-between gap-2">
                    <p className="min-w-0 truncate text-sm font-medium text-navy-950">{r.document}</p>
                    <OutcomeBadge outcome={r.outcome} />
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {country(r.country)} · {r.organization ?? r.recipient} · {formatDateTime(r.at)}
                  </p>
                </li>
              ))}
            </ul>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
                  <tr>
                    <th className="px-5 py-2.5 font-medium">When</th>
                    <th className="px-3 py-2.5 font-medium">Document</th>
                    <th className="px-3 py-2.5 font-medium">Recipient</th>
                    <th className="px-3 py-2.5 font-medium">Country</th>
                    <th className="px-3 py-2.5 font-medium">Client</th>
                    <th className="px-5 py-2.5 font-medium">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {log.data.rows.map((r) => (
                    <tr key={r.id}>
                      <td className="px-5 py-2.5 whitespace-nowrap text-slate-600">{formatDateTime(r.at)}</td>
                      <td className="max-w-[14rem] truncate px-3 py-2.5 font-medium text-navy-950">
                        {r.document}
                        {r.resource === 'file' && <Badge className="ml-1.5">file</Badge>}
                      </td>
                      <td className="px-3 py-2.5 text-slate-600">{r.organization ?? r.recipient}</td>
                      <td className="px-3 py-2.5 whitespace-nowrap">{country(r.country)}</td>
                      <td className="px-3 py-2.5 text-slate-500">{r.client}</td>
                      <td className="px-5 py-2.5">
                        <OutcomeBadge outcome={r.outcome} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 text-sm text-slate-600 sm:px-5">
              <span>
                {log.data.total} attempt{log.data.total === 1 ? '' : 's'}
              </span>
              <div className="flex gap-2">
                <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button size="sm" variant="secondary" disabled={page * log.data.pageSize >= log.data.total} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
      <p className="text-center text-xs text-slate-400">
        Locations are approximate and never include full IP addresses.{' '}
        <a href="https://db-ip.com" target="_blank" rel="noreferrer noopener" className="underline">
          IP Geolocation by DB-IP
        </a>
      </p>
    </div>
  );
}

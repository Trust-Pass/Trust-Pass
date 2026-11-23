import { SECURITY_EVENT_LABELS, type SystemSettings } from '@trustpass/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, Building2, CheckCircle2, FileText, HeartPulse, Link2, ShieldAlert, Users, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Alert, Badge, Button, Card, CardHeader, Field, Input, PageHeader, Select, Spinner, StatCard, Tabs } from '../components/ui';
import { api, errorMessage } from '../lib/api';
import { useMe } from '../lib/auth';
import { formatDateTime } from '../lib/format';

type Tab = 'overview' | 'users' | 'orgs' | 'events' | 'issuers' | 'settings' | 'health';

function Overview() {
  const { data } = useQuery({
    queryKey: ['admin', 'overview'],
    queryFn: () => api<{ users: number; suspendedUsers: number; organizations: number; documents: number; activeLinks: number; attempts24h: number; denied24h: number; highEvents24h: number }>('/api/admin/overview'),
  });
  if (!data) return <Spinner />;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatCard label="Users" value={data.users} icon={<Users className="size-4" />} hint={`${data.suspendedUsers} suspended`} />
      <StatCard label="Organizations" value={data.organizations} icon={<Building2 className="size-4" />} />
      <StatCard label="Documents" value={data.documents} icon={<FileText className="size-4" />} />
      <StatCard label="Active links" value={data.activeLinks} icon={<Link2 className="size-4" />} tone="teal" />
      <StatCard label="Access attempts (24h)" value={data.attempts24h} icon={<Activity className="size-4" />} />
      <StatCard label="Denied (24h)" value={data.denied24h} icon={<XCircle className="size-4" />} tone={data.denied24h ? 'red' : 'slate'} />
      <StatCard label="Warnings (24h)" value={data.highEvents24h} icon={<ShieldAlert className="size-4" />} tone={data.highEvents24h ? 'amber' : 'slate'} />
    </div>
  );
}

function UsersTab() {
  const me = useMe();
  const queryClient = useQueryClient();
  const [q, setQ] = useState('');
  const { data } = useQuery({
    queryKey: ['admin', 'users', q],
    queryFn: () =>
      api<{ users: Array<{ id: string; email: string; fullName: string; accountType: string; role: string; status: string; createdAt: string; documents: number; links: number; lockedUntil: string | null }> }>(
        `/api/admin/users?q=${encodeURIComponent(q)}`,
      ),
  });
  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api(`/api/admin/users/${id}`, { method: 'PATCH', body: { status } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['admin', 'users'] }),
  });
  return (
    <Card>
      <div className="p-4">
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or email" aria-label="Search users" />
      </div>
      <p className="px-4 pb-2 text-[13px] text-slate-500">Admins see account details only. There is no way to open a user's documents from here.</p>
      <ul className="divide-y divide-slate-100">
        {data?.users.map((u) => (
          <li key={u.id} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="font-medium text-ink">
                {u.fullName} {u.role === 'admin' && <Badge tone="navy">admin</Badge>} {u.status === 'suspended' && <Badge tone="red">suspended</Badge>}
              </p>
              <p className="truncate text-[13px] text-slate-500">
                {u.email} · {u.accountType} · {u.documents} docs · {u.links} links · joined {formatDateTime(u.createdAt)}
              </p>
            </div>
            {u.id !== me.user.id && (
              <Button size="sm" variant={u.status === 'active' ? 'secondary' : 'primary'} loading={setStatus.isPending && setStatus.variables?.id === u.id} onClick={() => setStatus.mutate({ id: u.id, status: u.status === 'active' ? 'suspended' : 'active' })}>
                {u.status === 'active' ? 'Suspend' : 'Reactivate'}
              </Button>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function OrgsTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ['admin', 'orgs'],
    queryFn: () => api<{ organizations: Array<{ id: string; name: string; type: string; status: string; members: number; receivedLinks: number; createdAt: string }> }>('/api/admin/organizations'),
  });
  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api(`/api/admin/organizations/${id}`, { method: 'PATCH', body: { status } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['admin', 'orgs'] }),
  });
  return (
    <Card>
      <ul className="divide-y divide-slate-100">
        {data?.organizations.map((o) => (
          <li key={o.id} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="font-medium text-ink">
                {o.name} {o.status === 'suspended' && <Badge tone="red">suspended</Badge>}
              </p>
              <p className="text-[13px] text-slate-500 capitalize">
                {o.type} · {o.members} members · {o.receivedLinks} links received
              </p>
            </div>
            <Button size="sm" variant="secondary" onClick={() => setStatus.mutate({ id: o.id, status: o.status === 'active' ? 'suspended' : 'active' })}>
              {o.status === 'active' ? 'Suspend' : 'Reactivate'}
            </Button>
          </li>
        ))}
        {data?.organizations.length === 0 && <li className="px-4 py-6 text-sm text-slate-500">No organizations yet.</li>}
      </ul>
    </Card>
  );
}

function EventsTab() {
  const [severity, setSeverity] = useState('');
  const [page, setPage] = useState(1);
  const qs = new URLSearchParams({ page: String(page), ...(severity ? { severity } : {}) });
  const { data } = useQuery({
    queryKey: ['admin', 'events', qs.toString()],
    queryFn: () => api<{ total: number; pageSize: number; events: Array<{ id: string; type: string; severity: string; at: string; user: string | null; actor: string | null }> }>(`/api/admin/security-events?${qs}`),
  });
  return (
    <Card>
      <div className="flex items-center justify-between gap-3 p-4">
        <Select aria-label="Severity" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} className="max-w-48">
          <option value="">All severities</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </Select>
        <span className="text-sm text-slate-500">{data?.total ?? 0} events</span>
      </div>
      <ul className="divide-y divide-slate-100">
        {data?.events.map((e) => (
          <li key={e.id} className="flex items-start justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <p className="text-sm font-medium text-ink">{SECURITY_EVENT_LABELS[e.type] ?? e.type.replace(/_/g, ' ')}</p>
              <p className="truncate text-xs text-slate-500">
                {e.user ?? 'platform'}
                {e.actor && e.actor !== e.user ? ` · by ${e.actor}` : ''} · {formatDateTime(e.at)}
              </p>
            </div>
            <Badge tone={e.severity === 'high' ? 'red' : e.severity === 'warning' ? 'amber' : 'slate'}>{e.severity}</Badge>
          </li>
        ))}
      </ul>
      <div className="flex justify-end gap-2 border-t border-slate-100 p-3">
        <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
        <Button size="sm" variant="secondary" disabled={!data || page * data.pageSize >= data.total} onClick={() => setPage((p) => p + 1)}>Next</Button>
      </div>
    </Card>
  );
}

function IssuersTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery({
    queryKey: ['admin', 'issuers'],
    queryFn: () => api<{ issuers: Array<{ id: string; name: string; identifier: string; kid: string; status: string; simulated: boolean; credentials: number }> }>('/api/admin/issuers'),
  });
  const setStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api(`/api/admin/issuers/${id}`, { method: 'PATCH', body: { status } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['admin', 'issuers'] }),
  });
  return (
    <div className="space-y-3">
      <Alert tone="info">Revoking an issuer means nothing it signed can be verified any more, immediately: its key is no longer trusted. Useful to demonstrate issuer compromise.</Alert>
      {data?.issuers.map((i) => (
        <Card key={i.id} className="p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="font-semibold text-ink">
                {i.name} {i.simulated && <Badge tone="amber">simulated</Badge>} <Badge tone={i.status === 'trusted' ? 'teal' : 'red'}>{i.status}</Badge>
              </p>
              <p className="mt-0.5 text-[13px] break-all text-slate-500">
                {i.identifier} · key {i.kid.slice(0, 16)}… · {i.credentials} credentials
              </p>
            </div>
            <Button size="sm" variant={i.status === 'trusted' ? 'danger' : 'primary'} loading={setStatus.isPending} onClick={() => setStatus.mutate({ id: i.id, status: i.status === 'trusted' ? 'revoked' : 'trusted' })}>
              {i.status === 'trusted' ? 'Revoke trust' : 'Trust again'}
            </Button>
          </div>
        </Card>
      ))}
    </div>
  );
}

function SettingsTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['admin', 'settings'], queryFn: () => api<{ settings: SystemSettings }>('/api/admin/settings') });
  const [form, setForm] = useState<SystemSettings | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    if (data) setForm(data.settings);
  }, [data]);
  const save = useMutation({
    mutationFn: (value: SystemSettings) => api('/api/admin/settings', { method: 'PUT', body: value }),
    onSuccess: () => {
      setMsg('Settings saved.');
      void queryClient.invalidateQueries({ queryKey: ['admin', 'settings'] });
    },
    onError: (err) => setMsg(errorMessage(err)),
  });
  if (!form) return <Spinner />;
  const num = (key: keyof SystemSettings) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: Number(e.target.value) });
  return (
    <Card className="max-w-xl space-y-4 p-5">
      <Field label="Maximum link lifetime (days)" htmlFor="maxLinkDays" hint="Owners cannot create links that last longer.">
        <Input id="maxLinkDays" type="number" min={1} max={365} value={form.maxLinkDays} onChange={num('maxLinkDays')} />
      </Field>
      <Field label="Access-log retention (days)" htmlFor="logRetentionDays" hint="Approximate locations are deleted after this period (data minimisation).">
        <Input id="logRetentionDays" type="number" min={7} max={730} value={form.logRetentionDays} onChange={num('logRetentionDays')} />
      </Field>
      <Field label="Demo credentials per user" htmlFor="credentialsPerUser">
        <Input id="credentialsPerUser" type="number" min={1} max={20} value={form.credentialsPerUser} onChange={num('credentialsPerUser')} />
      </Field>
      {msg && <Alert tone={save.isError ? 'error' : 'success'}>{msg}</Alert>}
      <Button onClick={() => save.mutate(form)} loading={save.isPending}>
        Save settings
      </Button>
    </Card>
  );
}

function HealthTab() {
  const { data, refetch, isFetching } = useQuery({
    queryKey: ['admin', 'health'],
    queryFn: () =>
      api<{ checks: Array<{ name: string; ok: boolean; detail: string }>; runtime: { uptimeSeconds: number; node: string; environment: string; memoryMb: number; masterKeyVersion: number; keyProvider: string } }>('/api/admin/health'),
  });
  const retention = useMutation({ mutationFn: () => api<{ result: Record<string, number> }>('/api/admin/retention/run', { method: 'POST' }) });
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title="Platform health" icon={<HeartPulse className="size-5" />} action={<Button size="sm" variant="secondary" loading={isFetching} onClick={() => refetch()}>Re-check</Button>} />
        <ul className="divide-y divide-slate-100">
          {data?.checks.map((c) => (
            <li key={c.name} className="flex items-start gap-3 px-5 py-3">
              {c.ok ? <CheckCircle2 className="mt-0.5 size-5 text-teal-400" /> : <XCircle className="mt-0.5 size-5 text-red-400" />}
              <div>
                <p className="text-sm font-medium text-ink">{c.name}</p>
                <p className="text-[13px] text-slate-600">{c.detail}</p>
              </div>
            </li>
          ))}
        </ul>
        {data && (
          <p className="border-t border-slate-100 px-5 py-3 text-[13px] text-slate-500">
            {data.runtime.environment} · Node {data.runtime.node} · up {Math.round(data.runtime.uptimeSeconds / 60)} min · {data.runtime.memoryMb} MB · keys: {data.runtime.keyProvider} v{data.runtime.masterKeyVersion}
          </p>
        )}
      </Card>
      <Card className="p-5">
        <p className="font-semibold text-ink">Log retention</p>
        <p className="mt-1 text-sm text-slate-600">Runs automatically every 6 hours. Audit tables only allow deletes from this job.</p>
        <Button className="mt-3" variant="secondary" loading={retention.isPending} onClick={() => retention.mutate()}>
          Run now
        </Button>
        {retention.data && (
          <p className="mt-3 text-sm text-slate-600">
            Deleted {retention.data.result.accessLogsDeleted} access logs, {retention.data.result.expiredSessionsDeleted} expired sessions.
          </p>
        )}
      </Card>
    </div>
  );
}

export function AdminPage() {
  const [tab, setTab] = useState<Tab>('overview');
  return (
    <div className="space-y-5">
      <PageHeader title="Administration" description="Manage accounts, organizations and issuers, and watch platform security." />
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'users', label: 'Users' },
          { value: 'orgs', label: 'Organizations' },
          { value: 'events', label: 'Security events' },
          { value: 'issuers', label: 'Issuers' },
          { value: 'settings', label: 'Settings' },
          { value: 'health', label: 'Health' },
        ]}
      />
      {tab === 'overview' && <Overview />}
      {tab === 'users' && <UsersTab />}
      {tab === 'orgs' && <OrgsTab />}
      {tab === 'events' && <EventsTab />}
      {tab === 'issuers' && <IssuersTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'health' && <HealthTab />}
    </div>
  );
}

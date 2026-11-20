import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Building2, ChevronRight, Inbox, ShieldCheck, UserPlus, Users } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router';
import { SharedDocument } from '../components/SharedDocument';
import {
  Alert,
  Badge,
  Button,
  ButtonLink,
  Card,
  CardHeader,
  EmptyState,
  Input,
  LinkStatusBadge,
  PageHeader,
  Select,
  Spinner,
  StatCard,
  Tabs,
  TrustBadge,
} from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { useMe } from '../lib/auth';
import { formatDateTime, relativeTime } from '../lib/format';
import type { LinkStatus, SharedView, TrustStatus } from '../lib/types';

interface OrgDetail {
  organization: { id: string; name: string; type: string; slug: string; createdAt: string };
  myRole: 'owner' | 'admin' | 'member';
  members: Array<{ userId: string; fullName: string; email: string; role: 'owner' | 'admin' | 'member'; since: string }>;
  stats: { receivedLinks: number; verifications: Partial<Record<TrustStatus, number>> };
}

interface InboxItem {
  id: string;
  document: { title: string; kind: string };
  sharedBy: string;
  organization: { id: string; name: string };
  fieldCount: number;
  includeFile: boolean;
  expiresAt: string;
  createdAt: string;
  status: LinkStatus;
}

export function OrganizationPage() {
  const me = useMe();
  const queryClient = useQueryClient();
  const [orgId, setOrgId] = useState(me.organizations[0]?.id ?? '');
  const [tab, setTab] = useState<'inbox' | 'members' | 'records'>('inbox');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'member' | 'admin'>('member');
  const [memberError, setMemberError] = useState<string | null>(null);

  const org = useQuery({ queryKey: ['org', orgId], queryFn: () => api<OrgDetail>(`/api/organizations/${orgId}`), enabled: Boolean(orgId) });
  const inbox = useQuery({ queryKey: ['inbox'], queryFn: () => api<{ items: InboxItem[] }>('/api/inbox') });
  const records = useQuery({
    queryKey: ['verify-records'],
    queryFn: () => api<{ records: Array<{ id: string; result: TrustStatus; method: string; reason: string; verifiedBy: string | null; createdAt: string }> }>('/api/verify/records'),
  });

  const addMember = useMutation({
    mutationFn: () => api(`/api/organizations/${orgId}/members`, { body: { email, role } }),
    onSuccess: () => {
      setEmail('');
      setMemberError(null);
      void queryClient.invalidateQueries({ queryKey: ['org', orgId] });
    },
    onError: (err) => setMemberError(err instanceof ApiError && err.fields.email ? err.fields.email : errorMessage(err)),
  });
  const updateRole = useMutation({
    mutationFn: ({ userId, newRole }: { userId: string; newRole: string }) => api(`/api/organizations/${orgId}/members/${userId}`, { method: 'PATCH', body: { role: newRole } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['org', orgId] }),
  });
  const removeMember = useMutation({
    mutationFn: (userId: string) => api(`/api/organizations/${orgId}/members/${userId}`, { method: 'DELETE' }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['org', orgId] }),
  });

  if (!orgId) {
    return <EmptyState icon={<Building2 className="size-6" />} title="You are not in an organization" body="Register an organization account, or ask an organization owner to add your email." />;
  }
  if (org.isLoading || !org.data) return <Spinner />;
  const o = org.data;
  const canManage = o.myRole === 'owner' || o.myRole === 'admin';
  const items = (inbox.data?.items ?? []).filter((i) => i.organization.id === orgId);

  const submitMember = (e: FormEvent) => {
    e.preventDefault();
    addMember.mutate();
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title={o.organization.name}
        description={`Organization dashboard · you are ${o.myRole}. Documents shared with the organization arrive here, already verified.`}
        actions={
          me.organizations.length > 1 ? (
            <Select aria-label="Organization" value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              {me.organizations.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </Select>
          ) : undefined
        }
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Documents received" value={o.stats.receivedLinks} icon={<Inbox className="size-4" />} />
        <StatCard label="Verified" value={o.stats.verifications.verified ?? 0} icon={<ShieldCheck className="size-4" />} tone="teal" />
        <StatCard label="Invalid" value={o.stats.verifications.invalid ?? 0} tone="red" />
        <StatCard label="Members" value={o.members.length} icon={<Users className="size-4" />} />
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: 'inbox', label: 'Received', count: items.length },
          { value: 'members', label: 'Members', count: o.members.length },
          { value: 'records', label: 'Verification records' },
        ]}
      />

      {tab === 'inbox' && (
        <Card>
          {items.length === 0 ? (
            <EmptyState
              icon={<Inbox className="size-6" />}
              title="Nothing received yet"
              body={`When someone shares a document with ${o.organization.name}, it appears here. Only members can open it.`}
            />
          ) : (
            <ul className="divide-y divide-slate-100">
              {items.map((i) => (
                <li key={i.id}>
                  <Link to={`/app/org/inbox/${i.id}`} className="flex items-center justify-between gap-3 px-4 py-3.5 hover:bg-slate-50 sm:px-5">
                    <div className="min-w-0">
                      <p className="truncate font-medium text-ink">{i.document.title}</p>
                      <p className="truncate text-[13px] text-slate-500">
                        From {i.sharedBy} · {i.fieldCount} field{i.fieldCount === 1 ? '' : 's'}
                        {i.includeFile && ' + file'} · {relativeTime(i.createdAt)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <LinkStatusBadge status={i.status} />
                      <ChevronRight className="size-5 text-slate-400" />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {tab === 'members' && (
        <div className="space-y-4">
          {canManage && (
            <Card className="p-4 sm:p-5">
              <form onSubmit={submitMember} className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <div className="flex-1">
                  <label htmlFor="member-email" className="mb-1.5 block text-sm font-medium text-ink">
                    Add a member by email
                  </label>
                  <Input id="member-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@example.com" required />
                </div>
                <Select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value as 'member' | 'admin')} className="sm:w-36">
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </Select>
                <Button type="submit" loading={addMember.isPending} icon={<UserPlus className="size-4" />}>
                  Add
                </Button>
              </form>
              {memberError && <Alert tone="error" className="mt-3">{memberError}</Alert>}
              <p className="mt-2 text-[13px] text-slate-500">They need a TrustPass account first. Members can open documents shared with the organization.</p>
            </Card>
          )}
          <Card>
            <ul className="divide-y divide-slate-100">
              {o.members.map((m) => (
                <li key={m.userId} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
                  <div className="min-w-0">
                    <p className="font-medium text-ink">
                      {m.fullName} {m.userId === me.user.id && <span className="text-slate-400">(you)</span>}
                    </p>
                    <p className="truncate text-[13px] text-slate-500">{m.email}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {o.myRole === 'owner' && m.userId !== me.user.id ? (
                      <Select aria-label={`Role of ${m.fullName}`} value={m.role} onChange={(e) => updateRole.mutate({ userId: m.userId, newRole: e.target.value })} className="h-9 w-32 py-1.5 text-sm">
                        <option value="owner">Owner</option>
                        <option value="admin">Admin</option>
                        <option value="member">Member</option>
                      </Select>
                    ) : (
                      <Badge tone="navy" className="capitalize">
                        {m.role}
                      </Badge>
                    )}
                    {canManage && m.userId !== me.user.id && (
                      <Button size="sm" variant="ghost" className="text-red-400" onClick={() => removeMember.mutate(m.userId)}>
                        Remove
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
            {(updateRole.error || removeMember.error) && <p className="px-5 pb-3 text-sm text-red-400">{errorMessage(updateRole.error ?? removeMember.error)}</p>}
          </Card>
        </div>
      )}

      {tab === 'records' && (
        <Card>
          <CardHeader title="Verification records" subtitle="Every authenticity check made by members of this organization." />
          {!records.data || records.data.records.length === 0 ? (
            <p className="px-5 py-6 text-sm text-slate-500">No checks yet.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {records.data.records.map((r) => (
                <li key={r.id} className="flex items-start justify-between gap-3 px-4 py-3 sm:px-5">
                  <div className="min-w-0">
                    <p className="text-sm text-ink">{r.reason}</p>
                    <p className="text-xs text-slate-500">
                      {r.verifiedBy} · {formatDateTime(r.createdAt)}
                    </p>
                  </div>
                  <TrustBadge status={r.result} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}

export function OrgInboxViewPage() {
  const { id = '' } = useParams();
  const { data, error, isLoading } = useQuery({ queryKey: ['inbox-item', id], queryFn: () => api<SharedView>(`/api/inbox/${id}`), retry: false, staleTime: Infinity });
  return (
    <div className="mx-auto max-w-3xl">
      <Link to="/app/org" className="mb-4 inline-flex items-center gap-1 text-sm font-medium text-accent">
        <ArrowLeft className="size-4" /> Organization inbox
      </Link>
      {isLoading && <Spinner label="Checking access" />}
      {error && (
        <Card>
          <EmptyState icon={<ShieldCheck className="size-6" />} title="Not available" body={errorMessage(error)} action={<ButtonLink to="/app/org">Back</ButtonLink>} />
        </Card>
      )}
      {data && <SharedDocument view={data} fileUrl={`/api/inbox/${id}/file`} />}
    </div>
  );
}

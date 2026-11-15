import { PASSWORD_MIN_LENGTH } from '@trustpass/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, LogOut, Monitor, UserRound } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Alert, Badge, Button, Card, CardHeader, Field, Input, PageHeader, Spinner } from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { useAuth, useMe } from '../lib/auth';
import { formatDate, relativeTime } from '../lib/format';

export function SettingsPage() {
  const me = useMe();
  const { refresh, logout } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [fullName, setFullName] = useState(me.user.fullName);
  const [profileMsg, setProfileMsg] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const [pw, setPw] = useState({ current: '', next: '' });
  const [pwMsg, setPwMsg] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);

  const sessions = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api<{ sessions: Array<{ id: string; client: string | null; createdAt: string; lastSeenAt: string; current: boolean }> }>('/api/me/sessions'),
  });

  const saveProfile = useMutation({
    mutationFn: () => api('/api/me', { method: 'PATCH', body: { fullName } }),
    onSuccess: async () => {
      await refresh();
      setProfileMsg({ tone: 'success', text: 'Profile saved.' });
    },
    onError: (err) => setProfileMsg({ tone: 'error', text: errorMessage(err) }),
  });
  const changePassword = useMutation({
    mutationFn: () => api('/api/me/password', { body: { currentPassword: pw.current, newPassword: pw.next } }),
    onSuccess: () => {
      setPw({ current: '', next: '' });
      setPwMsg({ tone: 'success', text: 'Password changed. Your other devices were signed out.' });
      void queryClient.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (err) => setPwMsg({ tone: 'error', text: err instanceof ApiError && err.fields.newPassword ? err.fields.newPassword : errorMessage(err) }),
  });
  const revokeSession = useMutation({
    mutationFn: (id: string) => api(`/api/me/sessions/${id}`, { method: 'DELETE' }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  });

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <PageHeader title="Profile and settings" />

      <Card>
        <CardHeader title="Profile" icon={<UserRound className="size-5" />} />
        <form
          className="space-y-4 p-4 sm:p-5"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            saveProfile.mutate();
          }}
        >
          <Field label="Full name" htmlFor="fullName">
            <Input id="fullName" value={fullName} onChange={(e) => setFullName(e.target.value)} maxLength={100} />
          </Field>
          <dl className="grid gap-3 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-slate-500">Email</dt>
              <dd className="font-medium break-all text-navy-950">{me.user.email}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Account type</dt>
              <dd className="font-medium text-navy-950 capitalize">{me.user.accountType}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Member since</dt>
              <dd className="font-medium text-navy-950">{formatDate(me.user.createdAt)}</dd>
            </div>
          </dl>
          {me.organizations.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {me.organizations.map((o) => (
                <Badge key={o.id} tone="navy">
                  {o.name} · {o.role}
                </Badge>
              ))}
            </div>
          )}
          {profileMsg && <Alert tone={profileMsg.tone}>{profileMsg.text}</Alert>}
          <Button type="submit" loading={saveProfile.isPending}>
            Save profile
          </Button>
        </form>
      </Card>

      <Card>
        <CardHeader title="Change password" subtitle="Changing it signs out every other device." icon={<KeyRound className="size-5" />} />
        <form
          className="space-y-4 p-4 sm:p-5"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            changePassword.mutate();
          }}
        >
          <Field label="Current password" htmlFor="current">
            <Input id="current" type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw((p) => ({ ...p, current: e.target.value }))} required />
          </Field>
          <Field label="New password" htmlFor="next" hint={`At least ${PASSWORD_MIN_LENGTH} characters.`}>
            <Input id="next" type="password" autoComplete="new-password" value={pw.next} onChange={(e) => setPw((p) => ({ ...p, next: e.target.value }))} required />
          </Field>
          {pwMsg && <Alert tone={pwMsg.tone}>{pwMsg.text}</Alert>}
          <Button type="submit" loading={changePassword.isPending}>
            Update password
          </Button>
        </form>
      </Card>

      <Card>
        <CardHeader title="Where you are signed in" subtitle="Sessions end after 1 hour of inactivity or 12 hours in total." icon={<Monitor className="size-5" />} />
        {sessions.isLoading || !sessions.data ? (
          <Spinner />
        ) : (
          <ul className="divide-y divide-slate-100">
            {sessions.data.sessions.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 px-4 py-3 sm:px-5">
                <div>
                  <p className="text-sm font-medium text-navy-950">
                    {s.client ?? 'Unknown device'} {s.current && <Badge tone="teal">This device</Badge>}
                  </p>
                  <p className="text-xs text-slate-500">
                    Signed in {relativeTime(s.createdAt)} · active {relativeTime(s.lastSeenAt)}
                  </p>
                </div>
                {!s.current && (
                  <Button size="sm" variant="secondary" onClick={() => revokeSession.mutate(s.id)}>
                    Sign out
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Button
        variant="secondary"
        className="w-full sm:w-auto"
        icon={<LogOut className="size-4" />}
        onClick={async () => {
          await logout();
          navigate('/login');
        }}
      >
        Sign out of this device
      </Button>
    </div>
  );
}

import { ORGANIZATION_TYPES, PASSWORD_MIN_LENGTH } from '@trustpass/shared';
import clsx from 'clsx';
import { Building2, Eye, EyeOff, Lock, User } from 'lucide-react';
import { useState, type FormEvent, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { Logo } from '../components/Logo';
import { Alert, Button, Field, Input, Select } from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { useAuth } from '../lib/auth';
import type { Me } from '../lib/types';

function AuthShell({ title, subtitle, children, footer }: { title: string; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <div className="hero-grid px-4 pt-6 pb-24 sm:pb-28">
        <div className="mx-auto max-w-md">
          <Link to="/">
            <Logo light />
          </Link>
        </div>
      </div>
      <div className="-mt-16 flex-1 px-4 pb-10 sm:-mt-20">
        <div className="mx-auto max-w-md surface-card glass rounded-3xl p-6 shadow-lift sm:p-8">
          <h1 className="text-2xl font-bold tracking-tight text-ink">{title}</h1>
          {subtitle && <p className="mt-1.5 text-sm text-slate-600">{subtitle}</p>}
          <div className="mt-6">{children}</div>
        </div>
        {footer && <div className="mx-auto mt-5 max-w-md text-center text-sm text-slate-600">{footer}</div>}
      </div>
    </div>
  );
}

function PasswordInput({ id, value, onChange, autoComplete, invalid }: { id: string; value: string; onChange: (v: string) => void; autoComplete: string; invalid?: boolean }) {
  const [show, setShow] = useState(false);
  return (
    <div className="relative">
      <Input id={id} type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} autoComplete={autoComplete} required invalid={invalid} className="pr-11" />
      <button type="button" onClick={() => setShow((s) => !s)} className="absolute top-1/2 right-2 -translate-y-1/2 rounded-lg p-1.5 text-slate-500 hover:bg-slate-100" aria-label={show ? 'Hide password' : 'Show password'}>
        {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </button>
    </div>
  );
}

function safeNext(next: string | null): string {
  // Only same-site paths: never redirect to another origin after sign-in.
  return next && next.startsWith('/') && !next.startsWith('//') ? next : '/app';
}

export function LoginPage() {
  const { signedIn } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await api<Me>('/api/auth/login', { body: { email, password } });
      signedIn(data);
      navigate(safeNext(params.get('next')), { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Sign in to manage and share your documents."
      footer={
        <>
          New to TrustPass?{' '}
          <Link to={`/register${params.get('next') ? `?next=${encodeURIComponent(params.get('next')!)}` : ''}`} className="font-semibold text-ink underline">
            Create an account
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && <Alert tone="error">{error}</Alert>}
        <Field label="Email" htmlFor="email">
          <Input id="email" type="email" inputMode="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label="Password" htmlFor="password">
          <PasswordInput id="password" value={password} onChange={setPassword} autoComplete="current-password" />
        </Field>
        <div className="text-right">
          <Link to="/forgot-password" className="text-sm font-medium text-accent hover:underline">
            Forgot your password?
          </Link>
        </div>
        <Button type="submit" className="w-full" size="lg" loading={loading} icon={<Lock className="size-4" />}>
          Sign in
        </Button>
      </form>
    </AuthShell>
  );
}

export function RegisterPage() {
  const { signedIn } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [accountType, setAccountType] = useState<'individual' | 'organization'>('individual');
  const [form, setForm] = useState({ fullName: '', email: '', password: '', organizationName: '', organizationType: 'company' });
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const set = (key: keyof typeof form) => (value: string) => setForm((f) => ({ ...f, [key]: value }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setFields({});
    setLoading(true);
    try {
      const body =
        accountType === 'organization'
          ? { accountType, ...form }
          : { accountType, fullName: form.fullName, email: form.email, password: form.password };
      const data = await api<Me>('/api/auth/register', { body });
      signedIn(data);
      navigate(safeNext(params.get('next')), { replace: true });
    } catch (err) {
      if (err instanceof ApiError) setFields(err.fields);
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const typeButton = (value: 'individual' | 'organization', label: string, hint: string, icon: ReactNode) => (
    <button
      type="button"
      role="radio"
      aria-checked={accountType === value}
      onClick={() => setAccountType(value)}
      className={clsx(
        'flex flex-1 flex-col items-start gap-1 rounded-2xl p-3.5 text-left ring-1 ring-inset transition-colors',
        accountType === value ? 'bg-blue-600 text-white ring-blue-400/60 shadow-glow' : 'bg-surface text-ink ring-slate-300 hover:bg-slate-50',
      )}
    >
      {icon}
      <span className="text-sm font-semibold">{label}</span>
      <span className={clsx('text-xs', accountType === value ? 'text-navy-200' : 'text-slate-500')}>{hint}</span>
    </button>
  );

  return (
    <AuthShell
      title="Create your account"
      subtitle="Free, and takes less than a minute."
      footer={
        <>
          Already registered?{' '}
          <Link to="/login" className="font-semibold text-ink underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4" noValidate>
        <div role="radiogroup" aria-label="Account type" className="flex gap-3">
          {typeButton('individual', 'Individual', 'Share my own documents', <User className="size-5" />)}
          {typeButton('organization', 'Organization', 'Receive and verify documents', <Building2 className="size-5" />)}
        </div>
        {error && <Alert tone="error">{error}</Alert>}
        {accountType === 'organization' && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-[1fr_auto]">
            <Field label="Organization name" htmlFor="org" error={fields.organizationName}>
              <Input id="org" value={form.organizationName} onChange={(e) => set('organizationName')(e.target.value)} required invalid={Boolean(fields.organizationName)} />
            </Field>
            <Field label="Type" htmlFor="orgType">
              <Select id="orgType" value={form.organizationType} onChange={(e) => set('organizationType')(e.target.value)}>
                {ORGANIZATION_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t[0]!.toUpperCase() + t.slice(1)}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        )}
        <Field label={accountType === 'organization' ? 'Your full name' : 'Full name'} htmlFor="name" error={fields.fullName}>
          <Input id="name" autoComplete="name" value={form.fullName} onChange={(e) => set('fullName')(e.target.value)} required invalid={Boolean(fields.fullName)} />
        </Field>
        <Field label="Email" htmlFor="email" error={fields.email}>
          <Input id="email" type="email" inputMode="email" autoComplete="email" value={form.email} onChange={(e) => set('email')(e.target.value)} required invalid={Boolean(fields.email)} />
        </Field>
        <Field label="Password" htmlFor="password" error={fields.password} hint={`At least ${PASSWORD_MIN_LENGTH} characters. A short sentence works well.`}>
          <PasswordInput id="password" value={form.password} onChange={set('password')} autoComplete="new-password" invalid={Boolean(fields.password)} />
        </Field>
        <Button type="submit" className="w-full" size="lg" loading={loading}>
          Create account
        </Button>
      </form>
    </AuthShell>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await api<{ message: string }>('/api/auth/password-reset/request', { body: { email } });
      setDone(res.message);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };
  return (
    <AuthShell title="Reset your password" subtitle="We will email you a link that works for 30 minutes." footer={<Link to="/login" className="font-semibold text-ink underline">Back to sign in</Link>}>
      {done ? (
        <Alert tone="success" title="Check your inbox">
          {done}
        </Alert>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          {error && <Alert tone="error">{error}</Alert>}
          <Field label="Email" htmlFor="email">
            <Input id="email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </Field>
          <Button type="submit" className="w-full" size="lg" loading={loading}>
            Send reset link
          </Button>
        </form>
      )}
    </AuthShell>
  );
}

export function ResetPasswordPage() {
  const navigate = useNavigate();
  // The token travels in the URL fragment, which browsers never send to servers or in Referer headers.
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? '';
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api('/api/auth/password-reset/confirm', { body: { token, password } });
      navigate('/login', { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };
  return (
    <AuthShell title="Choose a new password" subtitle="All your other sessions will be signed out.">
      {!token ? (
        <Alert tone="error">This reset link is incomplete. Request a new one.</Alert>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          {error && <Alert tone="error">{error}</Alert>}
          <Field label="New password" htmlFor="password" hint={`At least ${PASSWORD_MIN_LENGTH} characters.`}>
            <PasswordInput id="password" value={password} onChange={setPassword} autoComplete="new-password" />
          </Field>
          <Button type="submit" className="w-full" size="lg" loading={loading}>
            Save new password
          </Button>
        </form>
      )}
    </AuthShell>
  );
}

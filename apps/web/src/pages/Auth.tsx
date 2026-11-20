import { ORGANIZATION_TYPES, PASSWORD_MIN_LENGTH } from '@trustpass/shared';
import clsx from 'clsx';
import { Building2, Eye, EyeOff, Lock, Mail, Scan, ShieldCheck, User } from 'lucide-react';
import { useState, type FormEvent, type InputHTMLAttributes, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router';
import { GuillocheRing } from '../components/GuillocheRing';
import { Logo } from '../components/Logo';
import { Alert, Button, Field, Input, Select } from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { useAuth } from '../lib/auth';
import type { Me } from '../lib/types';

function AuthShell({ title, subtitle, children, footer }: { title: string; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="relative min-h-dvh overflow-x-clip">
      {/* A soft turquoise light behind the ring. */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(54rem_40rem_at_50%_46%,rgb(34_227_208/0.15),transparent_62%)]" aria-hidden />

      <header className="page-pad relative mx-auto flex h-20 max-w-6xl items-center justify-between">
        <Link to="/" aria-label="TrustPass home">
          <Logo />
        </Link>
      </header>

      <main className="relative">
        <section className="page-pad mx-auto max-w-3xl pt-4 text-center sm:pt-8">
          <p className="text-[30px] leading-tight font-semibold tracking-[-0.03em] text-white sm:text-[46px]">
            Your documents <span className="text-glow">Your control</span>
          </p>
          <p className="mt-3 text-[15px] text-slate-600 sm:text-lg">A secure and simple way to encrypt, share, and verify your documents.</p>
        </section>

        {/* The ring section is as tall as the ring, so the ring never runs into the text above or below. */}
        <section className="relative flex min-h-[min(820px,128vw)] items-center justify-center px-4 py-8">
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center" aria-hidden>
            <GuillocheRing draw className="aspect-square w-[min(790px,125vw)] max-w-none shrink-0" />
          </div>
          <div className="glass-card relative w-full max-w-[35rem] rounded-[28px] px-6 py-8 sm:px-10 sm:py-10">
            <h1 className="text-center text-[28px] font-semibold text-white sm:text-[32px]">{title}</h1>
            {subtitle && <p className="mt-2 text-center text-[15px] text-slate-600 sm:text-base">{subtitle}</p>}
            <div className="mt-7">{children}</div>
            {footer && <div className="mt-6 text-center text-[15px] text-slate-600">{footer}</div>}
          </div>
        </section>

        <section className="page-pad mx-auto max-w-3xl pt-2 pb-14" aria-labelledby="powered-by">
          <div className="flex items-center gap-5">
            <span className="h-px flex-1 bg-gradient-to-r from-transparent to-accent/50" aria-hidden />
            <h2 id="powered-by" className="text-[13px] font-medium tracking-[0.32em] text-slate-600 uppercase">
              Powered by
            </h2>
            <span className="h-px flex-1 bg-gradient-to-l from-transparent to-accent/50" aria-hidden />
          </div>
          <ul className="mt-8 grid grid-cols-3 gap-4 text-center">
            {[
              { icon: Lock, title: 'AES-256-GCM', body: 'Encryption' },
              { icon: Scan, title: 'QR Security', body: 'Secure access' },
              { icon: ShieldCheck, title: 'Verification', body: 'Integrity & trust' },
            ].map(({ icon: Icon, title: t, body }) => (
              <li key={t} className="flex flex-col items-center">
                <Icon className="size-8 text-accent drop-shadow-[0_0_10px_rgb(34_227_208/0.7)]" strokeWidth={1.6} aria-hidden />
                <p className="mt-3 text-[15px] font-semibold text-white sm:text-[17px]">{t}</p>
                <p className="text-[13px] text-slate-600 sm:text-[15px]">{body}</p>
              </li>
            ))}
          </ul>
        </section>
      </main>
    </div>
  );
}

/** A field in the sign-in card: icon inside, placeholder as the visible hint, label for screen readers. */
function GateInput({ id, label, icon, trailing, ...rest }: InputHTMLAttributes<HTMLInputElement> & { id: string; label: string; icon: ReactNode; trailing?: ReactNode }) {
  return (
    <div className="gate-input flex h-14 items-center gap-3 rounded-2xl px-4 transition-[border-color,box-shadow]">
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <span className="text-slate-600" aria-hidden>
        {icon}
      </span>
      <input id={id} className="h-full min-w-0 flex-1 bg-transparent text-[16px] text-white placeholder:text-slate-500 focus:outline-none" {...rest} />
      {trailing}
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
  const [showPassword, setShowPassword] = useState(false);
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
      subtitle="Sign in to access your secure vault."
      footer={
        <>
          Don’t have an account?{' '}
          <Link to={`/register${params.get('next') ? `?next=${encodeURIComponent(params.get('next')!)}` : ''}`} className="font-semibold text-glow hover:underline">
            Create one
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && <Alert tone="error">{error}</Alert>}
        <GateInput id="email" label="Email" icon={<Mail className="size-5" />} type="email" inputMode="email" autoComplete="email" placeholder="Email address" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <GateInput
          id="password"
          label="Password"
          icon={<Lock className="size-5" />}
          type={showPassword ? 'text' : 'password'}
          autoComplete="current-password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          trailing={
            <button type="button" onClick={() => setShowPassword((v) => !v)} className="-mr-1 rounded-lg p-1.5 text-slate-600 hover:text-white" aria-label={showPassword ? 'Hide password' : 'Show password'}>
              {showPassword ? <Eye className="size-5" /> : <EyeOff className="size-5" />}
            </button>
          }
        />
        <div className="text-right">
          <Link to="/forgot-password" className="text-[15px] font-semibold text-glow hover:underline">
            Forgot password?
          </Link>
        </div>
        <Button type="submit" size="xl" className="w-full" loading={loading}>
          Sign In
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
        accountType === value ? 'bg-accent/15 text-ink ring-accent/60 shadow-glow-teal' : 'bg-surface text-ink ring-slate-300 hover:bg-slate-50',
      )}
    >
      {icon}
      <span className="text-sm font-semibold">{label}</span>
      <span className={clsx('text-xs', accountType === value ? 'text-slate-600' : 'text-slate-500')}>{hint}</span>
    </button>
  );

  return (
    <AuthShell
      title="Create your account"
      subtitle="Free, and takes less than a minute."
      footer={
        <>
          Already registered?{' '}
          <Link to="/login" className="font-semibold text-glow hover:underline">
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
    <AuthShell title="Reset your password" subtitle="We will email you a link that works for 30 minutes." footer={<Link to="/login" className="font-semibold text-glow hover:underline">Back to sign in</Link>}>
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

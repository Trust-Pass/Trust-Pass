import { useQuery } from '@tanstack/react-query';
import { Ban, Clock, Globe2, Link2Off, LogIn, ShieldX } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, useLocation, useParams } from 'react-router';
import { Logo } from '../components/Logo';
import { SharedDocument } from '../components/SharedDocument';
import { ButtonLink, Spinner } from '../components/ui';
import { api, ApiError } from '../lib/api';
import { useAuth } from '../lib/auth';
import type { SharedView } from '../lib/types';

const DENIALS: Record<string, { icon: ReactNode; title: string }> = {
  link_expired: { icon: <Clock className="size-7" />, title: 'This link has expired' },
  link_revoked: { icon: <Ban className="size-7" />, title: 'This link was revoked' },
  country_blocked: { icon: <Globe2 className="size-7" />, title: 'Not available in your location' },
  country_unknown: { icon: <Globe2 className="size-7" />, title: 'Location could not be confirmed' },
  login_required: { icon: <LogIn className="size-7" />, title: 'Sign in to open this document' },
  not_recipient: { icon: <ShieldX className="size-7" />, title: 'This document is for someone else' },
  link_not_found: { icon: <Link2Off className="size-7" />, title: 'Link not found' },
};

export function RecipientPage() {
  const { token = '' } = useParams();
  const location = useLocation();
  const { me } = useAuth();
  const query = useQuery({
    queryKey: ['share', token, me?.user.id ?? 'anon'],
    queryFn: () => api<SharedView>(`/api/share/${encodeURIComponent(token)}`),
    retry: false,
    staleTime: Infinity,
  });

  const error = query.error instanceof ApiError ? query.error : null;
  const denial = error ? (DENIALS[error.code] ?? { icon: <ShieldX className="size-7" />, title: 'This document is not available' }) : null;

  return (
    <div className="min-h-dvh">
      <header className="glass border-b border-white/[0.06]">
        <div className="page-pad mx-auto flex h-14 max-w-3xl items-center justify-between">
          <Link to="/">
            <Logo />
          </Link>
          <span className="text-xs font-medium text-slate-500">Secure share</span>
        </div>
      </header>
      <main className="page-pad mx-auto max-w-3xl py-6 sm:py-10">
        {query.isLoading && <Spinner label="Checking access" />}
        {query.data && <SharedDocument view={query.data} fileUrl={`/api/share/${encodeURIComponent(token)}/file`} />}
        {denial && error && (
          <div className="surface-card rounded-3xl px-6 py-12 text-center" data-testid="access-denied" data-code={error.code}>
            <div className="mx-auto inline-flex rounded-2xl bg-accent-soft p-3.5 text-accent">{denial.icon}</div>
            <h1 className="mt-4 text-xl font-bold text-ink">{denial.title}</h1>
            <p className="mx-auto mt-2 max-w-md text-[15px] text-slate-600">{error.message}</p>
            {error.code === 'login_required' && (
              <ButtonLink to={`/login?next=${encodeURIComponent(location.pathname)}`} className="mt-6" icon={<LogIn className="size-4" />}>
                Sign in
              </ButtonLink>
            )}
            {(error.code === 'link_expired' || error.code === 'link_revoked') && (
              <p className="mt-4 text-sm text-slate-500">Ask the person who shared it to send you a new link.</p>
            )}
            {error.code.startsWith('country') && (
              <p className="mt-4 text-sm text-slate-500">The owner limited where this document can be opened. Location is estimated from your internet connection.</p>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

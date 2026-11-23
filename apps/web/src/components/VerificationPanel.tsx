import clsx from 'clsx';
import { CalendarX2, CheckCircle2, ShieldAlert, ShieldCheck, ShieldQuestion, XCircle } from 'lucide-react';
import { formatDate } from '../lib/format';
import type { Verification } from '../lib/types';

const STYLES = {
  verified: {
    icon: ShieldCheck,
    title: 'Verified',
    box: 'bg-teal-50 ring-teal-200',
    iconBox: 'bg-teal-500 text-navy-950',
    text: 'text-teal-950',
  },
  invalid: {
    icon: ShieldAlert,
    title: 'Invalid',
    box: 'bg-red-50 ring-red-200',
    iconBox: 'bg-red-600 text-white',
    text: 'text-red-950',
  },
  expired: {
    icon: CalendarX2,
    title: 'Expired',
    box: 'bg-slate-100 ring-slate-300',
    iconBox: 'bg-slate-500 text-white',
    text: 'text-slate-900',
  },
  unverified: {
    icon: ShieldQuestion,
    title: 'Unverified',
    box: 'bg-amber-50 ring-amber-200',
    iconBox: 'bg-amber-400 text-navy-950',
    text: 'text-amber-950',
  },
};

export function VerificationPanel({
  verification,
  compact = false,
  unverifiedTitle,
}: {
  verification: Verification;
  compact?: boolean;
  /** The Verify page says "Unable to verify"; other pages keep "Unverified". */
  unverifiedTitle?: string;
}) {
  const style = verification.result === 'unverified' && unverifiedTitle ? { ...STYLES.unverified, title: unverifiedTitle } : STYLES[verification.result];
  const Icon = style.icon;
  return (
    <div className={clsx('rounded-2xl p-4 ring-1 ring-inset sm:p-5', style.box)} data-testid="verification-result" data-result={verification.result}>
      <div className="flex items-start gap-3">
        <div className={clsx('rounded-xl p-2', style.iconBox)}>
          <Icon className="size-6" aria-hidden />
        </div>
        <div className={clsx('min-w-0', style.text)}>
          <p className="text-lg font-bold">{style.title}</p>
          <p className="mt-0.5 text-sm leading-relaxed opacity-90">{verification.reason}</p>
          {verification.issuer && (
            <p className="mt-2 text-sm">
              Issuer: <span className="font-semibold">{verification.issuer.name}</span>
              {verification.issuer.simulated && <span className="ml-1.5 rounded-full bg-surface/70 px-2 py-0.5 text-xs font-medium">Simulated for demo</span>}
            </p>
          )}
          {verification.expiresAt && verification.result !== 'unverified' && (
            <p className="mt-1 text-sm opacity-80">Credential valid until {formatDate(verification.expiresAt)}</p>
          )}
        </div>
      </div>

      {!compact && verification.checks.length > 0 && (
        <ul className="mt-4 space-y-2 border-t border-black/5 pt-3">
          {verification.checks.map((check) => (
            <li key={check.name} className="flex items-start gap-2 text-sm">
              {check.passed ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-teal-400" /> : <XCircle className="mt-0.5 size-4 shrink-0 text-red-400" />}
              <span>
                <span className="font-medium text-ink">{check.name}:</span> <span className="text-slate-700">{check.detail}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

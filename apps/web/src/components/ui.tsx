import clsx from 'clsx';
import { AlertTriangle, CalendarX2, Check, CheckCircle2, Copy, Info, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion, X, XCircle } from 'lucide-react';
import {
  forwardRef,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import { Link, type LinkProps } from 'react-router';
import type { AccessOutcome, LinkStatus, TrustStatus } from '../lib/types';

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'teal' | 'band';
type Size = 'sm' | 'md' | 'lg' | 'xl';

const variants: Record<Variant, string> = {
  primary: 'btn-primary font-semibold shadow-glow',
  teal: 'btn-teal font-semibold shadow-glow',
  secondary: 'bg-white/[0.035] text-ink ring-1 ring-inset ring-accent/20 hover:bg-white/[0.07] hover:ring-accent/40 active:bg-white/[0.02]',
  ghost: 'text-ink hover:bg-white/[0.06] active:bg-white/[0.03]',
  /** Outline button for use on a lit band. */
  band: 'text-ink ring-1 ring-inset ring-accent/30 bg-white/[0.03] hover:bg-white/[0.08] hover:ring-accent/50',
  danger: 'bg-red-600 text-white hover:bg-red-500 active:bg-red-600 shadow-sm',
};
const sizes: Record<Size, string> = {
  sm: 'h-9 px-3 text-sm gap-1.5 rounded-xl',
  md: 'h-11 px-4 text-sm gap-2 rounded-xl',
  lg: 'h-12 px-6 text-base gap-2 rounded-xl',
  xl: 'h-14 px-6 text-[17px] gap-2 rounded-2xl',
};

export function buttonClass(variant: Variant = 'primary', size: Size = 'md', extra?: string) {
  return clsx(
    'inline-flex items-center justify-center font-medium transition-[background,box-shadow,transform,color] duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-55 select-none whitespace-nowrap',
    variants[variant],
    sizes[size],
    extra,
  );
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', loading, icon, className, children, disabled, type = 'button', ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={buttonClass(variant, size, className)} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 className="size-4 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
});

export function ButtonLink({ variant = 'primary', size = 'md', className, icon, children, ...rest }: LinkProps & { variant?: Variant; size?: Size; icon?: ReactNode }) {
  return (
    <Link className={buttonClass(variant, size, className)} {...rest}>
      {icon}
      {children}
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------

export function Card({ className, children, as: Tag = 'div' }: { className?: string; children: ReactNode; as?: 'div' | 'section' | 'article' }) {
  return <Tag className={clsx('surface-card rounded-[20px]', className)}>{children}</Tag>;
}

export function CardHeader({ title, subtitle, action, icon }: { title: ReactNode; subtitle?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-3.5 sm:px-5">
      <div className="flex min-w-0 items-start gap-2.5">
        {icon && <div className="mt-0.5 text-accent">{icon}</div>}
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-ink">{title}</h2>
          {subtitle && <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

export function PageHeader({ title, description, actions, back }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; back?: ReactNode }) {
  return (
    <div className="mb-5 animate-rise sm:mb-7">
      {back}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold text-ink sm:text-[30px] sm:leading-[1.15]">{title}</h1>
          {description && <p className="mt-1.5 max-w-2xl text-[15px] text-slate-600">{description}</p>}
        </div>
        {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
      </div>
    </div>
  );
}

export function StatCard({ label, value, hint, icon, tone = 'navy' }: { label: string; value: ReactNode; hint?: ReactNode; icon?: ReactNode; tone?: 'navy' | 'teal' | 'red' | 'amber' | 'slate' }) {
  const tones = {
    navy: 'bg-accent-soft text-accent',
    teal: 'bg-teal-50 text-teal-700',
    red: 'bg-red-50 text-red-400',
    amber: 'bg-amber-50 text-amber-700',
    slate: 'bg-slate-100 text-slate-600',
  };
  return (
    <Card className="relative overflow-hidden p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-[13px] font-medium text-slate-500">{label}</p>
        {icon && <div className={clsx('rounded-lg p-1.5 ring-1 ring-inset ring-accent/15', tones[tone])}>{icon}</div>}
      </div>
      <p className="num mt-2 text-[30px] leading-none font-semibold text-ink tabular-nums">{value}</p>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
    </Card>
  );
}

export function EmptyState({ icon, title, body, action }: { icon: ReactNode; title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <div className="mb-3 rounded-2xl bg-accent-soft p-3 text-accent">{icon}</div>
      <p className="font-semibold text-ink">{title}</p>
      {body && <p className="mt-1 max-w-sm text-sm text-slate-500">{body}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center justify-center gap-2 py-12 text-sm text-slate-500">
      <Loader2 className="size-5 animate-spin text-teal-400" aria-hidden />
      {label}…
    </div>
  );
}

// ---------------------------------------------------------------------------
// Feedback
// ---------------------------------------------------------------------------

type AlertTone = 'info' | 'success' | 'warning' | 'error';
const alertStyles: Record<AlertTone, { box: string; icon: ReactNode }> = {
  info: { box: 'bg-accent-soft text-ink ring-accent-line', icon: <Info className="size-5 text-accent" /> },
  success: { box: 'bg-teal-50 text-teal-950 ring-teal-100', icon: <CheckCircle2 className="size-5 text-teal-400" /> },
  warning: { box: 'bg-amber-50 text-amber-950 ring-amber-100', icon: <AlertTriangle className="size-5 text-amber-400" /> },
  error: { box: 'bg-red-50 text-red-900 ring-red-100', icon: <XCircle className="size-5 text-red-400" /> },
};

export function Alert({ tone = 'info', title, children, className }: { tone?: AlertTone; title?: ReactNode; children?: ReactNode; className?: string }) {
  const style = alertStyles[tone];
  return (
    <div role={tone === 'error' ? 'alert' : 'status'} className={clsx('flex gap-3 rounded-xl px-4 py-3 text-sm ring-1 ring-inset', style.box, className)}>
      <div className="shrink-0 pt-px">{style.icon}</div>
      <div className="min-w-0">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={clsx(title && 'mt-0.5', 'leading-relaxed opacity-90')}>{children}</div>}
      </div>
    </div>
  );
}

type BadgeTone = 'teal' | 'red' | 'amber' | 'slate' | 'navy' | 'green';
const badgeTones: Record<BadgeTone, string> = {
  teal: 'bg-teal-50 text-teal-800 ring-teal-200',
  green: 'bg-emerald-50 text-emerald-800 ring-emerald-200',
  red: 'bg-red-50 text-red-700 ring-red-200',
  amber: 'bg-amber-50 text-amber-800 ring-amber-200',
  slate: 'bg-slate-100 text-slate-700 ring-slate-200',
  navy: 'bg-accent-soft text-ink ring-accent-line',
};

export function Badge({ tone = 'slate', children, icon, className }: { tone?: BadgeTone; children: ReactNode; icon?: ReactNode; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset whitespace-nowrap', badgeTones[tone], className)}>
      {icon}
      {children}
    </span>
  );
}

export function TrustBadge({ status, size = 'sm', unverifiedLabel = 'Unverified' }: { status: TrustStatus; size?: 'sm' | 'lg'; unverifiedLabel?: string }) {
  const map = {
    verified: { tone: 'teal' as const, label: 'Verified', Icon: ShieldCheck },
    invalid: { tone: 'red' as const, label: 'Invalid', Icon: ShieldAlert },
    expired: { tone: 'slate' as const, label: 'Expired', Icon: CalendarX2 },
    unverified: { tone: 'amber' as const, label: unverifiedLabel, Icon: ShieldQuestion },
  }[status];
  return (
    <Badge tone={map.tone} className={size === 'lg' ? 'px-3 py-1 text-sm' : undefined} icon={<map.Icon className={size === 'lg' ? 'size-4' : 'size-3.5'} aria-hidden />}>
      {map.label}
    </Badge>
  );
}

export function LinkStatusBadge({ status }: { status: LinkStatus }) {
  if (status === 'active') return <Badge tone="green">● Active</Badge>;
  if (status === 'expired') return <Badge tone="slate">Expired</Badge>;
  return <Badge tone="red">Revoked</Badge>;
}

export const OUTCOME_UI: Record<AccessOutcome, { label: string; tone: BadgeTone }> = {
  granted: { label: 'Granted', tone: 'green' },
  denied_country: { label: 'Country blocked', tone: 'red' },
  denied_expired: { label: 'Link expired', tone: 'slate' },
  denied_revoked: { label: 'Link revoked', tone: 'slate' },
  denied_recipient: { label: 'Not the recipient', tone: 'amber' },
};

export function OutcomeBadge({ outcome }: { outcome: AccessOutcome }) {
  const ui = OUTCOME_UI[outcome];
  return <Badge tone={ui.tone}>{ui.label}</Badge>;
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

export function Field({ label, error, hint, children, htmlFor }: { label: ReactNode; error?: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {children}
      {error ? <p className="text-sm text-red-400">{error}</p> : hint ? <p className="text-[13px] text-slate-500">{hint}</p> : null}
    </div>
  );
}

const inputBase =
  'block w-full rounded-xl border-0 bg-slate-50/80 px-3.5 py-2.5 text-ink shadow-sm ring-1 ring-inset ring-slate-300 transition-shadow placeholder:text-slate-400 focus:ring-2 focus:ring-inset focus:ring-accent focus:shadow-[0_0_0_4px_rgb(var(--glow)/0.14)] focus:outline-none disabled:bg-slate-50 disabled:text-slate-500';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(function Input(
  { className, invalid, ...rest },
  ref,
) {
  return <input ref={ref} className={clsx(inputBase, invalid && 'ring-red-400', className)} aria-invalid={invalid || undefined} {...rest} />;
});

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={clsx(inputBase, 'pr-9', className)} {...rest}>
      {children}
    </select>
  );
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={clsx(inputBase, 'min-h-28 font-mono text-[13px]', className)} {...rest} />;
}

export function Toggle({ checked, onChange, label, description }: { checked: boolean; onChange: (v: boolean) => void; label: ReactNode; description?: ReactNode }) {
  const id = useId();
  return (
    <label htmlFor={id} className="flex cursor-pointer items-start justify-between gap-4">
      <span>
        <span className="block text-sm font-medium text-ink">{label}</span>
        {description && <span className="mt-0.5 block text-[13px] text-slate-500">{description}</span>}
      </span>
      <span className="relative mt-0.5 inline-flex shrink-0">
        <input id={id} type="checkbox" className="peer sr-only" checked={checked} onChange={(e) => onChange(e.target.checked)} />
        <span className="h-6 w-11 rounded-full bg-slate-300 transition-colors peer-checked:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent" />
        <span className="absolute top-0.5 left-0.5 size-5 rounded-full bg-white shadow transition-transform peer-checked:translate-x-5" />
      </span>
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: Array<{ value: T; label: ReactNode }>; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap gap-2">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={clsx(
            'h-10 rounded-xl px-3.5 text-sm font-medium ring-1 ring-inset transition-colors',
            value === o.value ? 'bg-accent/15 text-ink ring-accent/60 shadow-glow-teal' : 'bg-surface text-ink ring-slate-300 hover:bg-slate-50',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: Array<{ value: T; label: ReactNode; count?: number }> }) {
  return (
    <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
      <div role="tablist" className="inline-flex gap-1 rounded-xl bg-slate-50/80 p-1 ring-1 ring-inset ring-slate-200">
        {tabs.map((t) => (
          <button
            key={t.value}
            role="tab"
            type="button"
            aria-selected={value === t.value}
            onClick={() => onChange(t.value)}
            className={clsx(
              'inline-flex h-9 items-center gap-1.5 rounded-lg px-3 text-sm font-medium whitespace-nowrap transition-colors',
              value === t.value ? 'bg-accent/15 text-ink shadow-sm ring-1 ring-inset ring-accent/40' : 'text-slate-600 hover:text-ink',
            )}
          >
            {t.label}
            {t.count !== undefined && <span className="rounded-full bg-slate-200 px-1.5 text-xs text-slate-700">{t.count}</span>}
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal (bottom sheet on phones, centred dialog on larger screens)
// ---------------------------------------------------------------------------

export function Modal({ open, onClose, title, children, footer }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      className="m-0 mt-auto w-full max-w-none rounded-t-3xl bg-surface-raised p-0 text-slate-800 shadow-lift ring-1 ring-slate-200 backdrop:bg-navy-950/70 backdrop:backdrop-blur-sm sm:m-auto sm:max-w-lg sm:rounded-2xl"
    >
      <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        <button type="button" onClick={onClose} className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100" aria-label="Close">
          <X className="size-5" />
        </button>
      </div>
      <div className="max-h-[70vh] overflow-y-auto px-5 py-4">{children}</div>
      {footer && <div className="safe-bottom flex flex-col-reverse gap-2 border-t border-slate-100 px-5 py-4 sm:flex-row sm:justify-end">{footer}</div>}
    </dialog>
  );
}

export function ConfirmModal({
  open,
  onClose,
  onConfirm,
  title,
  body,
  confirmLabel,
  loading,
  danger = true,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  loading?: boolean;
  danger?: boolean;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} loading={loading}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="text-sm leading-relaxed text-slate-600">{body}</div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Copy to clipboard
// ---------------------------------------------------------------------------

export function CopyButton({ value, label = 'Copy', size = 'sm', variant = 'secondary' }: { value: string; label?: string; size?: Size; variant?: Variant }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant={variant}
      size={size}
      icon={copied ? <Check className="size-4" /> : <Copy className="size-4" />}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
        } catch {
          const el = document.createElement('textarea');
          el.value = value;
          document.body.appendChild(el);
          el.select();
          document.execCommand('copy');
          el.remove();
        }
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }}
    >
      {copied ? 'Copied' : label}
    </Button>
  );
}

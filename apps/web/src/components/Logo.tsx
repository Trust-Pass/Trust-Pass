import clsx from 'clsx';

export function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <path d="M32 6 52 14v15c0 13-8.5 23.8-20 27-11.5-3.2-20-14-20-27V14z" fill="#14b8a6" />
      <path d="m23 32 6.5 6.5L42 26" fill="none" stroke="#0b1b3b" strokeWidth="5.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ light = false, className }: { light?: boolean; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <ShieldMark className="size-8" />
      <span className={clsx('text-lg font-bold tracking-tight', light ? 'text-white' : 'text-navy-950')}>
        Trust<span className="text-teal-500">Pass</span>
      </span>
    </span>
  );
}

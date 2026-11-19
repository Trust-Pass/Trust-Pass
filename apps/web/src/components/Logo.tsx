import clsx from 'clsx';
import { useId } from 'react';

export function ShieldMark({ className }: { className?: string }) {
  // Unique per instance: a gradient defined inside a hidden copy (e.g. the closed drawer) would not paint.
  const gradientId = `tp-shield-${useId().replace(/:/g, '')}`;
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <defs>
        <linearGradient id={gradientId} x1="12" y1="6" x2="52" y2="58" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5eead4" />
          <stop offset="1" stopColor="#3b82f6" />
        </linearGradient>
      </defs>
      <path d="M32 6 52 14v15c0 13-8.5 23.8-20 27-11.5-3.2-20-14-20-27V14z" fill={`url(#${gradientId})`} />
      <path d="M32 6 52 14v15c0 13-8.5 23.8-20 27V6z" fill="#ffffff" fillOpacity="0.12" />
      <path d="m23 32 6.5 6.5L42 26" fill="none" stroke="#06102a" strokeWidth="5.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ className }: { /** Kept for callers; the logo is light on every background now. */ light?: boolean; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <ShieldMark className="size-8" />
      <span className={clsx('text-lg font-bold tracking-tight', 'text-white')}>
        Trust<span className="bg-gradient-to-r from-teal-300 to-blue-400 bg-clip-text text-transparent">Pass</span>
      </span>
    </span>
  );
}

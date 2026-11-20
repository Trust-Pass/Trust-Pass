import clsx from 'clsx';
import { useId } from 'react';

/** The TrustPass mark: a turquoise-to-emerald shield engraved with the rings of the seal. */
export function ShieldMark({ className }: { className?: string }) {
  // Unique per instance: a gradient defined inside a hidden copy (e.g. the closed drawer) would not paint.
  const id = `tp-shield-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <defs>
        <linearGradient id={id} x1="14" y1="6" x2="50" y2="58" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7af7ea" />
          <stop offset="0.55" stopColor="#22e3d0" />
          <stop offset="1" stopColor="#0ea594" />
        </linearGradient>
      </defs>
      <path d="M32 5 53 13v16c0 13.5-8.8 24.6-21 28-12.2-3.4-21-14.5-21-28V13z" fill={`url(#${id})`} />
      <g fill="none" stroke="#021412" strokeOpacity="0.18" strokeWidth="0.9">
        <circle cx="32" cy="30" r="17" />
        <circle cx="32" cy="30" r="12.5" />
      </g>
      <path d="m23.5 30.5 6 6L41 25" fill="none" stroke="#021412" strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo({ className }: { /** Kept for callers; the logo reads on every dark surface. */ light?: boolean; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2.5', className)}>
      <ShieldMark className="size-8 drop-shadow-[0_0_12px_rgb(34_227_208/0.35)]" />
      <span className="text-lg font-semibold tracking-[-0.02em] text-white">TrustPass</span>
    </span>
  );
}

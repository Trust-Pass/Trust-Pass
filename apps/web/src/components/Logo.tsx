import clsx from 'clsx';

/** The TrustPass mark: a shield engraved with the rings of the seal, and a check. */
export function ShieldMark({ className, light = false }: { className?: string; light?: boolean }) {
  const fill = light ? '#b7dacb' : '#0a6a4e';
  const line = light ? '#0a2d23' : '#ffffff';
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden>
      <path d="M32 5 53 13v16c0 13.5-8.8 24.6-21 28-12.2-3.4-21-14.5-21-28V13z" fill={fill} />
      <g fill="none" stroke={line} strokeOpacity="0.22" strokeWidth="0.9">
        <circle cx="32" cy="30" r="17" />
        <circle cx="32" cy="30" r="12.5" />
      </g>
      <path d="m23.5 30.5 6 6L41 25" fill="none" stroke={line} strokeWidth="4.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** `light`: for use on the dark green bands (pale mark, white name). */
export function Logo({ light = false, className }: { light?: boolean; className?: string }) {
  return (
    <span className={clsx('inline-flex items-center gap-2', className)}>
      <ShieldMark className="size-8" light={light} />
      <span className={clsx('text-lg font-semibold tracking-[-0.02em]', light ? 'text-white' : 'text-ink')}>TrustPass</span>
    </span>
  );
}

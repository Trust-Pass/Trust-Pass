import clsx from 'clsx';
import { ShieldCheck } from 'lucide-react';
import { useMemo } from 'react';

/**
 * The TrustPass rosette: a guilloché seal like the ones printed on passports and banknotes.
 * Three rings, each made of ten phase-shifted wave circles that weave into a fine mesh.
 * With `draw`, the lines draw themselves the first time the seal appears (skipped when the
 * visitor prefers reduced motion, see index.css).
 */

function band(R: number, amp: number, lobes: number, copies: number, steps: number, ripple = 0) {
  const parts: string[] = [];
  for (let j = 0; j < copies; j++) {
    const phase = (j * 2 * Math.PI) / copies;
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * Math.PI * 2;
      const r = R + amp * Math.sin(lobes * t + phase) + ripple * Math.sin(3 * lobes * t - phase);
      parts.push(`${i === 0 ? 'M' : 'L'}${(100 + r * Math.cos(t)).toFixed(1)} ${(100 + r * Math.sin(t)).toFixed(1)}`);
    }
  }
  return parts.join('');
}

export function Seal({ size = 160, className, draw = false, emblem = true, label }: { size?: number; className?: string; draw?: boolean; emblem?: boolean; label?: string }) {
  const rings = useMemo(() => [band(86, 9, 24, 10, 540, 2), band(60, 10, 16, 10, 400), band(34, 12, 8, 10, 260)], []);
  return (
    <span className={clsx('relative inline-flex shrink-0 items-center justify-center', className)} style={{ width: size, height: size }}>
      <svg viewBox="0 0 200 200" width={size} height={size} className={clsx('absolute inset-0', draw && 'seal-draw')} role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true}>
        <g fill="none" stroke="currentColor" strokeWidth={0.35}>
          {rings.map((d, i) => (
            <path key={i} d={d} pathLength={1} />
          ))}
        </g>
        <g fill="none" stroke="currentColor" opacity={0.55}>
          <circle cx="100" cy="100" r="98" strokeWidth={0.6} />
          <circle cx="100" cy="100" r="74" strokeWidth={0.4} />
          <circle cx="100" cy="100" r="47" strokeWidth={0.4} />
        </g>
      </svg>
      {emblem && <ShieldCheck className="relative" style={{ width: size * 0.17, height: size * 0.17 }} strokeWidth={1.5} aria-hidden />}
    </span>
  );
}

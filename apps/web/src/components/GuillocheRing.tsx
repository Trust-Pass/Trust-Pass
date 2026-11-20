import clsx from 'clsx';
import { memo, useMemo } from 'react';

/**
 * The large TrustPass guilloché ring: a woven lace of looped curves outside, fine mesh bands
 * inside, like the rosettes engraved on passports and banknotes. Computed once (pure geometry),
 * drawn as glowing turquoise lines with an emerald halo. Decorative: hidden from screen readers.
 */

const C = 100;

function band(R: number, amp: number, lobes: number, copies: number, steps: number, ripple = 0) {
  const out: string[] = [];
  for (let j = 0; j < copies; j++) {
    const ph = (j * 2 * Math.PI) / copies;
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * Math.PI * 2;
      const r = R + amp * Math.sin(lobes * t + ph) + ripple * Math.sin(3 * lobes * t - ph);
      out.push(`${i === 0 ? 'M' : 'L'}${(C + r * Math.cos(t)).toFixed(2)} ${(C + r * Math.sin(t)).toFixed(2)}`);
    }
  }
  return out.join('');
}

/** Loops riding around a circle: radial reach `a`, sideways reach `b`; copies interleave into lace. */
function lace(R: number, n: number, a: number, b: number, copies: number, steps: number) {
  const out: string[] = [];
  for (let j = 0; j < copies; j++) {
    const ph = (j * 2 * Math.PI) / copies;
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * Math.PI * 2;
      const r = R + a * Math.cos(n * t + ph);
      const th = t + (b / R) * Math.sin(n * t + ph);
      out.push(`${i === 0 ? 'M' : 'L'}${(C + r * Math.cos(th)).toFixed(2)} ${(C + r * Math.sin(th)).toFixed(2)}`);
    }
  }
  return out.join('');
}

export const GuillocheRing = memo(function GuillocheRing({ className, draw = false }: { className?: string; draw?: boolean }) {
  const rings = useMemo(
    () => ({
      lace: lace(90.5, 44, 7.4, 9.5, 3, 2400),
      fine: band(78, 2.6, 72, 7, 1600),
      mesh: band(63, 7, 28, 8, 1000, 1.5),
      core: band(47.5, 5, 18, 6, 640),
    }),
    [],
  );
  return (
    <svg viewBox="-1 -1 202 202" className={clsx('guilloche-ring', draw && 'seal-draw', className)} aria-hidden focusable="false">
      <g fill="none" stroke="currentColor" strokeLinejoin="round">
        <path d={rings.lace} strokeWidth={0.3} pathLength={1} />
        <path d={rings.fine} strokeWidth={0.22} opacity={0.8} pathLength={1} />
        <path d={rings.mesh} strokeWidth={0.22} opacity={0.7} pathLength={1} />
        <path d={rings.core} strokeWidth={0.2} opacity={0.5} pathLength={1} />
      </g>
      <g fill="none" stroke="currentColor">
        <circle cx={C} cy={C} r="99" strokeWidth={0.35} opacity={0.55} />
        <circle cx={C} cy={C} r="82.4" strokeWidth={0.35} opacity={0.6} />
        <circle cx={C} cy={C} r="72.5" strokeWidth={0.3} opacity={0.5} />
      </g>
    </svg>
  );
});

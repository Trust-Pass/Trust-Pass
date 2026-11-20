import { useId, useMemo, useState } from 'react';

export interface DayPoint {
  date: string;
  granted: number;
  denied: number;
}

const W = 640;
const H = 200;
const TOP = 16;
const BOTTOM = 10;

/** Smooth curve through the points (horizontal-tangent cubic segments: never overshoots). */
function curve(points: Array<[number, number]>) {
  return points.reduce((d, [x, y], i) => {
    if (i === 0) return `M${x.toFixed(1)},${y.toFixed(1)}`;
    const [px, py] = points[i - 1]!;
    const cx = (px + x) / 2;
    return `${d} C${cx.toFixed(1)},${py.toFixed(1)} ${cx.toFixed(1)},${y.toFixed(1)} ${x.toFixed(1)},${y.toFixed(1)}`;
  }, '');
}

const dayLabel = (iso: string) => new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' });

/**
 * Granted views as a luminous line with a soft fill; blocked attempts as crimson bars on the same
 * time axis. Hover or focus a day to read its numbers.
 */
export function AccessChart({ days }: { days: DayPoint[] }) {
  const gid = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const [active, setActive] = useState<number | null>(null);
  const { line, area, xs, ys, max } = useMemo(() => {
    const max = Math.max(4, ...days.map((d) => d.granted), ...days.map((d) => d.denied));
    const step = days.length > 1 ? W / (days.length - 1) : W;
    const xs = days.map((_, i) => i * step);
    const ys = days.map((d) => H - BOTTOM - (d.granted / max) * (H - TOP - BOTTOM));
    const line = curve(xs.map((x, i) => [x, ys[i]!]));
    return { line, area: `${line} L${W},${H} L0,${H} Z`, xs, ys, max };
  }, [days]);
  const sel = active ?? null;
  const total = days.reduce((n, d) => n + d.granted + d.denied, 0);

  return (
    <div className="relative" onMouseLeave={() => setActive(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-48 w-full overflow-visible sm:h-52" role="img" aria-label={`Access over the last ${days.length} days: ${total} attempts`}>
        <defs>
          <linearGradient id={`fill-${gid}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#22e3d0" stopOpacity="0.38" />
            <stop offset="1" stopColor="#22e3d0" stopOpacity="0" />
          </linearGradient>
          <linearGradient id={`line-${gid}`} x1="0" x2="1">
            <stop offset="0" stopColor="#10b981" />
            <stop offset="0.5" stopColor="#22e3d0" />
            <stop offset="1" stopColor="#7af7ea" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <line key={f} x1="0" x2={W} y1={H - BOTTOM - f * (H - TOP - BOTTOM)} y2={H - BOTTOM - f * (H - TOP - BOTTOM)} stroke="rgb(34 227 208 / 0.06)" vectorEffect="non-scaling-stroke" />
        ))}
        <path d={area} fill={`url(#fill-${gid})`} />
        <path d={line} fill="none" stroke="#22e3d0" strokeOpacity="0.35" strokeWidth="8" vectorEffect="non-scaling-stroke" style={{ filter: 'blur(5px)' }} />
        <path d={line} fill="none" stroke={`url(#line-${gid})`} strokeWidth="2.2" vectorEffect="non-scaling-stroke" />
        {days.map((d, i) =>
          d.denied > 0 ? (
            <rect key={`b${d.date}`} x={xs[i]! - 5} y={H - BOTTOM - (d.denied / max) * (H - TOP - BOTTOM) * 0.6} width="10" height={(d.denied / max) * (H - TOP - BOTTOM) * 0.6} rx="3" fill="#f43f5e" fillOpacity="0.85" />
          ) : null,
        )}
        {sel !== null && <line x1={xs[sel]} x2={xs[sel]} y1={TOP / 2} y2={H} stroke="rgb(122 247 234 / 0.4)" strokeDasharray="3 4" vectorEffect="non-scaling-stroke" />}
        {days.map((d, i) => (
          <rect
            key={`h${d.date}`}
            x={Math.max(0, xs[i]! - W / days.length / 2)}
            y="0"
            width={W / days.length}
            height={H}
            fill="transparent"
            onMouseEnter={() => setActive(i)}
            onClick={() => setActive(i)}
          />
        ))}
      </svg>
      {sel !== null && (
        <>
          <span
            className="pointer-events-none absolute size-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-[#7af7ea] bg-[#04110d] shadow-[0_0_12px_rgb(34_227_208/0.8)]"
            style={{ left: `${(xs[sel]! / W) * 100}%`, top: `${(ys[sel]! / H) * 100}%` }}
          />
          <div
            className="glass pointer-events-none absolute top-0 z-10 rounded-xl px-3 py-2 text-xs ring-1 ring-accent/25"
            style={{ left: `clamp(0px, calc(${(xs[sel]! / W) * 100}% - 60px), calc(100% - 130px))` }}
            data-testid="chart-tooltip"
          >
            <p className="num text-sm font-semibold text-ink">
              {days[sel]!.granted} {days[sel]!.granted === 1 ? 'view' : 'views'}
            </p>
            <p className="text-slate-500">
              {dayLabel(days[sel]!.date)} · {days[sel]!.denied} blocked
            </p>
          </div>
        </>
      )}
      <div className="mt-2 flex justify-between font-mono text-[11px] text-slate-500">
        {days
          .filter((_, i) => i % Math.ceil(days.length / 5) === 0 || i === days.length - 1)
          .map((d) => (
            <span key={d.date}>{dayLabel(d.date)}</span>
          ))}
      </div>
      <p className="sr-only">Highest day: {max} attempts.</p>
    </div>
  );
}

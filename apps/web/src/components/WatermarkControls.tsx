import {
  WATERMARK_DEFAULT_TEXT,
  WATERMARK_STYLE_LABELS,
  type WatermarkColor,
  type WatermarkSettings,
  type WatermarkStrength,
  type WatermarkStyle,
} from '@trustpass/shared';
import clsx from 'clsx';
import { Stamp } from 'lucide-react';
import { Field, Input, Segmented, Toggle } from './ui';

const SWATCHES: Record<WatermarkColor, { label: string; hex: string }> = {
  navy: { label: 'Navy', hex: '#0b1b3b' },
  teal: { label: 'Teal', hex: '#086b63' },
  crimson: { label: 'Crimson', hex: '#8c0f1f' },
  gray: { label: 'Graphite', hex: '#4d5260' },
};
const STRENGTH_OPACITY: Record<WatermarkStrength, number> = { light: 0.09, medium: 0.16, strong: 0.26 };

/** A small page that shows what the chosen watermark looks like, drawn the same way as the PDF. */
function WatermarkSample({ value, recipient }: { value: WatermarkSettings; recipient: string }) {
  const color = SWATCHES[value.color].hex;
  const bands = value.style !== 'diagonal';
  const stamp = value.style !== 'bands';
  const word = (value.text || WATERMARK_DEFAULT_TEXT).toUpperCase();
  return (
    <div className="relative mx-auto aspect-[1/1.3] w-full max-w-[150px] overflow-hidden rounded-md bg-white shadow-card ring-1 ring-slate-300" aria-hidden="true">
      {/* Body text lines of a document */}
      <div className="absolute inset-x-4 top-9 space-y-1.5">
        {[90, 75, 82, 60, 88, 70, 50].map((w, i) => (
          <div key={i} className="h-1 rounded-full bg-slate-300" style={{ width: `${w}%` }} />
        ))}
      </div>
      {value.enabled && stamp && (
        <div className="absolute inset-0 flex flex-col items-center justify-around py-6">
          {[0, 1].map((i) => (
            <span key={i} className="-rotate-[30deg] whitespace-nowrap text-[13px] font-bold tracking-wide" style={{ color, opacity: STRENGTH_OPACITY[value.strength] * 3.2 }}>
              {word}
            </span>
          ))}
        </div>
      )}
      {value.enabled && bands && (
        <>
          <div className="absolute inset-x-0 top-0 px-1.5 py-1 text-[5.5px] leading-tight text-white" style={{ background: color }}>
            <span className="block truncate font-bold">{word} - Shared with: {recipient || 'the recipient'}</span>
            <span className="block truncate">Viewed: date, time | Link reference</span>
          </div>
          <div className="absolute inset-x-0 bottom-0 truncate px-1.5 py-0.5 text-[5.5px] text-white" style={{ background: color }}>
            Viewed: date, time | Link reference
          </div>
        </>
      )}
    </div>
  );
}

/**
 * The owner's watermark choice for one link. The server draws exactly this on every view and
 * download (or nothing at all when it is off).
 */
export function WatermarkControls({ value, onChange, recipient }: { value: WatermarkSettings; onChange: (v: WatermarkSettings) => void; recipient: string }) {
  const set = <K extends keyof WatermarkSettings>(key: K, v: WatermarkSettings[K]) => onChange({ ...value, [key]: v });
  return (
    <div className="space-y-4" data-testid="watermark-controls">
      <Toggle
        checked={value.enabled}
        onChange={(v) => set('enabled', v)}
        label={
          <span className="flex items-center gap-1.5">
            <Stamp className="size-4" /> Watermark the file
          </span>
        }
        description={
          value.enabled
            ? 'Every view and download shows the recipient, the time and a link reference, so a leaked copy can be traced.'
            : 'No watermark is drawn on the recipient’s copy. Views and downloads are still logged, but a leaked copy will not show who it came from.'
        }
      />
      {value.enabled && (
        <div className="grid gap-4 sm:grid-cols-[1fr_150px] sm:items-start">
          <div className="space-y-4">
            <div>
              <p className="mb-2 text-[13px] font-medium text-slate-600">Style</p>
              <Segmented
                label="Watermark style"
                value={value.style}
                onChange={(v: WatermarkStyle) => set('style', v)}
                options={(Object.keys(WATERMARK_STYLE_LABELS) as WatermarkStyle[]).map((k) => ({ value: k, label: WATERMARK_STYLE_LABELS[k] }))}
              />
            </div>
            {value.style !== 'bands' && (
              <Field label="Stamp text" htmlFor="wm-text" hint="Latin letters, digits and basic punctuation, up to 24 characters.">
                <Input
                  id="wm-text"
                  value={value.text}
                  maxLength={24}
                  onChange={(e) => set('text', e.target.value)}
                  placeholder={WATERMARK_DEFAULT_TEXT}
                />
              </Field>
            )}
            <div>
              <p className="mb-2 text-[13px] font-medium text-slate-600">Colour</p>
              <div role="radiogroup" aria-label="Watermark colour" className="flex flex-wrap gap-2">
                {(Object.keys(SWATCHES) as WatermarkColor[]).map((c) => (
                  <button
                    key={c}
                    type="button"
                    role="radio"
                    aria-checked={value.color === c}
                    onClick={() => set('color', c)}
                    className={clsx(
                      'inline-flex h-9 items-center gap-2 rounded-xl px-3 text-sm ring-1 ring-inset transition-colors',
                      value.color === c ? 'bg-accent-soft text-ink ring-accent-line' : 'text-slate-600 ring-slate-300 hover:bg-slate-50',
                    )}
                  >
                    <span className="size-3.5 rounded-full ring-1 ring-white/30" style={{ background: SWATCHES[c].hex }} />
                    {SWATCHES[c].label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <p className="mb-2 text-[13px] font-medium text-slate-600">Strength</p>
              <Segmented
                label="Watermark strength"
                value={value.strength}
                onChange={(v: WatermarkStrength) => set('strength', v)}
                options={[
                  { value: 'light', label: 'Light' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'strong', label: 'Strong' },
                ]}
              />
            </div>
          </div>
          <div className="hidden sm:block">
            <WatermarkSample value={value} recipient={recipient} />
            <p className="mt-2 text-center text-[11px] text-slate-500">Sample. Use “Preview recipient copy” for the real file.</p>
          </div>
        </div>
      )}
    </div>
  );
}

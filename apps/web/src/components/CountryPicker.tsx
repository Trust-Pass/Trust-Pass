import { COUNTRY_CODES, countryName, SUGGESTED_COUNTRIES } from '@trustpass/shared';
import clsx from 'clsx';
import { Search, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { flag } from '../lib/format';
import { Input } from './ui';

export function CountryPicker({ value, onChange }: { value: string[]; onChange: (codes: string[]) => void }) {
  const [query, setQuery] = useState('');
  const all = useMemo(
    () => COUNTRY_CODES.map((code) => ({ code, name: countryName(code) })).sort((a, b) => a.name.localeCompare(b.name)),
    [],
  );
  const q = query.trim().toLowerCase();
  const matches = q ? all.filter((c) => c.name.toLowerCase().includes(q) || c.code.toLowerCase() === q).slice(0, 30) : [];
  const toggle = (code: string) => onChange(value.includes(code) ? value.filter((c) => c !== code) : [...value, code]);

  return (
    <div className="space-y-3">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-2" aria-label="Allowed countries">
          {value.map((code) => (
            <span key={code} className="inline-flex items-center gap-1.5 rounded-full bg-teal-50 py-1 pr-1 pl-3 text-sm font-medium text-teal-900 ring-1 ring-teal-200">
              {flag(code)} {countryName(code)}
              <button type="button" onClick={() => toggle(code)} className="rounded-full p-1 hover:bg-teal-100" aria-label={`Remove ${countryName(code)}`}>
                <X className="size-3.5" />
              </button>
            </span>
          ))}
        </div>
      )}

      <div>
        <p className="mb-2 text-xs font-semibold tracking-wide text-slate-500 uppercase">Quick picks</p>
        <div className="flex flex-wrap gap-2">
          {SUGGESTED_COUNTRIES.map((code) => (
            <button
              key={code}
              type="button"
              aria-pressed={value.includes(code)}
              onClick={() => toggle(code)}
              className={clsx(
                'h-9 rounded-full px-3 text-sm ring-1 ring-inset transition-colors',
                value.includes(code) ? 'bg-accent/15 text-ink ring-accent/60 shadow-glow-teal' : 'bg-surface text-ink ring-slate-300 hover:bg-slate-50',
              )}
            >
              {flag(code)} {countryName(code)}
            </button>
          ))}
        </div>
      </div>

      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-slate-400" />
        <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search other countries" className="pl-9" aria-label="Search countries" />
      </div>
      {matches.length > 0 && (
        <ul className="max-h-56 overflow-y-auto rounded-xl ring-1 ring-slate-200">
          {matches.map((c) => (
            <li key={c.code}>
              <label className="flex cursor-pointer items-center gap-3 px-3 py-2.5 text-sm hover:bg-slate-50">
                <input type="checkbox" checked={value.includes(c.code)} onChange={() => toggle(c.code)} className="size-4 rounded accent-teal-600" />
                <span>
                  {flag(c.code)} {c.name}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

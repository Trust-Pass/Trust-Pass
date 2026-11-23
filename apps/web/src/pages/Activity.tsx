import { SECURITY_EVENT_LABELS, SIGN_IN_EVENT_TYPES } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import { Eye, EyeOff, ScrollText } from 'lucide-react';
import { useState } from 'react';
import { Badge, Button, Card, EmptyState, PageHeader, Select, Spinner } from '../components/ui';
import { api } from '../lib/api';
import { formatDateTime } from '../lib/format';

interface ActivityPageData {
  page: number;
  pageSize: number;
  total: number;
  hiddenSignIns: number;
  events: Array<{ id: string; type: string; severity: 'info' | 'warning' | 'high'; at: string; document: string | null; byYou: boolean; metadata: Record<string, unknown> }>;
}

function describe(meta: Record<string, unknown>): string | null {
  const parts: string[] = [];
  if (typeof meta.recipient === 'string') parts.push(`Recipient: ${meta.recipient}`);
  if (typeof meta.client === 'string') parts.push(meta.client);
  if (typeof meta.result === 'string') parts.push(`Result: ${meta.result}`);
  if (typeof meta.algorithm === 'string') parts.push(`${meta.algorithm}, key v${String(meta.kekVersion ?? 1)}`);
  if (Array.isArray(meta.after)) parts.push(`Countries: ${(meta.after as string[]).join(', ') || 'any'}`);
  if (typeof meta.expiresAt === 'string') parts.push(`Expires ${formatDateTime(meta.expiresAt)}`);
  if (typeof meta.source === 'string' && typeof meta.kind === 'string') {
    const sources: Record<string, string> = { camera: 'Live camera', image: 'Image', paste: 'Pasted' };
    const from = sources[meta.source] ?? meta.source;
    parts.push(`${from} · ${meta.kind.replace(/_/g, ' ')}`);
  }
  return parts.length ? parts.join(' · ') : null;
}

const HIDE_SIGN_INS_KEY = 'trustpass.activity.hideSignIns';
const SIGN_IN_TYPES: readonly string[] = SIGN_IN_EVENT_TYPES;

/** The choice is remembered in this browser; it only changes what is shown, never the log. */
function readHideSignIns(): boolean {
  try {
    return window.localStorage.getItem(HIDE_SIGN_INS_KEY) === '1';
  } catch {
    return false;
  }
}

export function ActivityPage() {
  const [page, setPage] = useState(1);
  const [type, setType] = useState('');
  const [hideSignIns, setHideSignIns] = useState(readHideSignIns);
  const toggleSignIns = () => {
    const next = !hideSignIns;
    setHideSignIns(next);
    setPage(1);
    if (next && SIGN_IN_TYPES.includes(type)) setType('');
    try {
      window.localStorage.setItem(HIDE_SIGN_INS_KEY, next ? '1' : '0');
    } catch {
      /* the choice then lasts for this visit only */
    }
  };
  const qs = new URLSearchParams({ page: String(page), ...(type ? { type } : {}), ...(hideSignIns ? { hideSignIns: '1' } : {}) });
  const { data, isLoading } = useQuery({ queryKey: ['activity', qs.toString()], queryFn: () => api<ActivityPageData>(`/api/activity?${qs}`) });

  return (
    <div>
      <PageHeader
        title="Activity log"
        description="Security events on your account. The log is append-only: the database rejects edits and deletions."
        actions={
          <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
            <Select
              aria-label="Event type"
              value={type}
              onChange={(e) => {
                setType(e.target.value);
                setPage(1);
              }}
              className="sm:w-60"
            >
              <option value="">All events</option>
              {Object.entries(SECURITY_EVENT_LABELS)
                .filter(([value]) => !(hideSignIns && SIGN_IN_TYPES.includes(value)))
                .map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
            </Select>
            <Button
              variant="secondary"
              aria-pressed={hideSignIns}
              icon={hideSignIns ? <Eye className="size-4" /> : <EyeOff className="size-4" />}
              onClick={toggleSignIns}
              className="shrink-0"
            >
              {hideSignIns ? 'Show hidden sign-in history' : 'Hide sign-in history'}
            </Button>
          </div>
        }
      />
      {hideSignIns && data && data.hiddenSignIns > 0 && (
        <p className="mb-3 text-[13px] text-slate-500" role="status" data-testid="sign-ins-hidden">
          {data.hiddenSignIns} sign-in record{data.hiddenSignIns === 1 ? ' is' : 's are'} hidden from this view. They stay in your security log.
        </p>
      )}
      <Card>
        {isLoading || !data ? (
          <Spinner />
        ) : data.events.length === 0 ? (
          <EmptyState icon={<ScrollText className="size-6" />} title="No events" />
        ) : (
          <>
            <ol className="divide-y divide-slate-100">
              {data.events.map((e) => {
                const detail = describe(e.metadata);
                return (
                  <li key={e.id} className="flex items-start justify-between gap-3 px-4 py-3.5 sm:px-5">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-ink">{SECURITY_EVENT_LABELS[e.type] ?? e.type.replace(/_/g, ' ')}</p>
                      {e.document && <p className="truncate text-sm text-slate-600">{e.document}</p>}
                      {detail && <p className="truncate text-xs text-slate-500">{detail}</p>}
                      <p className="mt-0.5 text-xs text-slate-400">
                        {formatDateTime(e.at)}
                        {!e.byYou && ' · by the system or another person'}
                      </p>
                    </div>
                    {e.severity !== 'info' && <Badge tone={e.severity === 'high' ? 'red' : 'amber'}>{e.severity === 'high' ? 'High' : 'Warning'}</Badge>}
                  </li>
                );
              })}
            </ol>
            <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 text-sm text-slate-600 sm:px-5">
              <span>{data.total} events</span>
              <div className="flex gap-2">
                <Button size="sm" variant="secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button size="sm" variant="secondary" disabled={page * data.pageSize >= data.total} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

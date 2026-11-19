import { SECURITY_EVENT_LABELS } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import { ScrollText } from 'lucide-react';
import { useState } from 'react';
import { Badge, Button, Card, EmptyState, PageHeader, Select, Spinner } from '../components/ui';
import { api } from '../lib/api';
import { formatDateTime } from '../lib/format';

interface ActivityPageData {
  page: number;
  pageSize: number;
  total: number;
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

export function ActivityPage() {
  const [page, setPage] = useState(1);
  const [type, setType] = useState('');
  const qs = new URLSearchParams({ page: String(page), ...(type ? { type } : {}) });
  const { data, isLoading } = useQuery({ queryKey: ['activity', qs.toString()], queryFn: () => api<ActivityPageData>(`/api/activity?${qs}`) });

  return (
    <div>
      <PageHeader
        title="Activity log"
        description="Security events on your account. The log is append-only: the database rejects edits and deletions."
        actions={
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
            {Object.entries(SECURITY_EVENT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </Select>
        }
      />
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

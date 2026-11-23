import { useQuery, useQueryClient } from '@tanstack/react-query';
import { FileSearch, FileUp, History, KeyRound } from 'lucide-react';
import { useRef, useState, type FormEvent } from 'react';
import { Alert, Button, Card, CardHeader, PageHeader, Spinner, Tabs, Textarea, TrustBadge } from '../components/ui';
import { VerificationPanel } from '../components/VerificationPanel';
import { api, errorMessage } from '../lib/api';
import { formatDateTime } from '../lib/format';
import type { TrustStatus, Verification } from '../lib/types';

interface RecordRow {
  id: string;
  result: TrustStatus;
  method: string;
  reason: string;
  issuer: string | null;
  verifiedBy: string | null;
  createdAt: string;
}

export function VerifyPage() {
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<'file' | 'credential'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [presentation, setPresentation] = useState('');
  const [result, setResult] = useState<Verification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const records = useQuery({ queryKey: ['verify-records'], queryFn: () => api<{ records: RecordRow[] }>('/api/verify/records') });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      let res: { verification: Verification };
      if (mode === 'file') {
        if (!file) throw new Error('Choose a file to check.');
        const form = new FormData();
        form.append('file', file);
        res = await api('/api/verify/file', { form });
      } else {
        res = await api('/api/verify/presentation', { body: { presentation } });
      }
      setResult(res.verification);
      void queryClient.invalidateQueries({ queryKey: ['verify-records'] });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Verify a document"
        description="Check whether a document or credential was signed by a trusted issuer and has not been changed since."
      />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="p-4 sm:p-5">
          <Tabs
            value={mode}
            onChange={(m) => {
              setMode(m);
              setResult(null);
              setError(null);
            }}
            tabs={[
              { value: 'file', label: 'Check a file' },
              { value: 'credential', label: 'Check a credential' },
            ]}
          />
          <form onSubmit={submit} className="mt-4 space-y-4">
            {mode === 'file' ? (
              <>
                <button
                  type="button"
                  onClick={() => fileInput.current?.click()}
                  className="flex w-full flex-col items-center rounded-2xl border-2 border-dashed border-slate-300 px-4 py-8 text-center hover:border-accent hover:bg-slate-50"
                >
                  <FileUp className="size-7 text-accent" />
                  <span className="mt-2 font-semibold text-ink">{file ? file.name : 'Choose a PDF certificate'}</span>
                  <span className="text-sm text-slate-500">TrustPass compares its SHA-256 fingerprint with the issuer's signed record.</span>
                </button>
                <input ref={fileInput} type="file" accept="application/pdf,image/png,image/jpeg" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="File to verify" />
              </>
            ) : (
              <div>
                <label htmlFor="presentation" className="mb-1.5 block text-sm font-medium text-ink">
                  Signed credential (SD-JWT)
                </label>
                <Textarea id="presentation" value={presentation} onChange={(e) => setPresentation(e.target.value)} placeholder="eyJhbGciOiJFZERTQSIs…~WyJ…~" rows={6} required />
                <p className="mt-1.5 text-[13px] text-slate-500">Paste the credential from a share link, or the one you downloaded from your document. Try editing one character to see it fail.</p>
              </div>
            )}
            {error && <Alert tone="error">{error}</Alert>}
            <Button type="submit" size="lg" className="w-full" loading={loading} icon={mode === 'file' ? <FileSearch className="size-5" /> : <KeyRound className="size-5" />}>
              Verify
            </Button>
          </form>
        </Card>

        <div className="space-y-4">
          {result ? (
            <div className="space-y-4">
              <VerificationPanel verification={result} unverifiedTitle="Unable to verify" />
              {result.claims.length > 0 && (
                <Card>
                  <CardHeader title="Disclosed fields" subtitle="Each one matched a digest signed by the issuer." />
                  <dl className="divide-y divide-slate-100">
                    {result.claims.map((c) => (
                      <div key={c.key} className="flex justify-between gap-3 px-4 py-2.5 text-sm sm:px-5">
                        <dt className="text-slate-500">{c.label}</dt>
                        <dd className="font-medium text-ink">{c.value}</dd>
                      </div>
                    ))}
                  </dl>
                </Card>
              )}
            </div>
          ) : (
            <Card className="p-5">
              <h2 className="font-semibold text-ink">What the results mean</h2>
              <ul className="mt-3 space-y-3 text-sm text-slate-600">
                <li className="flex items-start gap-3">
                  <span className="shrink-0"><TrustBadge status="verified" /></span> The digital signature is valid and the signing key belongs to a trusted issuer registered in TrustPass.
                </li>
                <li className="flex items-start gap-3">
                  <span className="shrink-0"><TrustBadge status="invalid" /></span> The signature does not match, or the document was changed after it was signed.
                </li>
                <li className="flex items-start gap-3">
                  <span className="shrink-0"><TrustBadge status="expired" /></span> The signature is valid and the document is unchanged, but the credential is past its validity period.
                </li>
                <li className="flex items-start gap-3">
                  <span className="shrink-0"><TrustBadge status="unverified" unverifiedLabel="Unable to verify" /></span> No supported digital signature, or the signer is not a trusted issuer in TrustPass. A document's look or issuer name is never enough.
                </li>
              </ul>
            </Card>
          )}
        </div>
      </div>

      <Card>
        <CardHeader title="Verification records" subtitle="Checks by you and your organization." icon={<History className="size-5" />} />
        {records.isLoading ? (
          <Spinner />
        ) : !records.data || records.data.records.length === 0 ? (
          <p className="px-5 py-6 text-sm text-slate-500">No verifications yet.</p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {records.data.records.map((r) => (
              <li key={r.id} className="flex items-start justify-between gap-3 px-4 py-3 sm:px-5">
                <div className="min-w-0">
                  <p className="text-sm text-ink">{r.reason}</p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {r.method === 'share_link' ? 'Opened via share link' : r.method === 'file' ? 'File check' : 'Credential check'}
                    {r.verifiedBy && ` · ${r.verifiedBy}`} · {formatDateTime(r.createdAt)}
                  </p>
                </div>
                <TrustBadge status={r.result} unverifiedLabel="Unable to verify" />
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

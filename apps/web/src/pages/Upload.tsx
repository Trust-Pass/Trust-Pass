import { DOCUMENT_CATEGORIES, DOCUMENT_CATEGORY_LABELS } from '@trustpass/shared';
import { useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowLeft, CheckCircle2, FileUp, KeyRound, Lock, Plus, Trash2 } from 'lucide-react';
import { useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { Alert, Button, Card, Field, Input, PageHeader, Select } from '../components/ui';
import { ApiError, errorMessage, uploadWithProgress } from '../lib/api';
import { formatBytes } from '../lib/format';

const MAX_MB = 10;

export function UploadPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState<string>('university_certificate');
  const [claims, setClaims] = useState<Array<{ label: string; value: string }>>([]);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fields, setFields] = useState<Record<string, string>>({});

  const choose = (f: File | undefined) => {
    if (!f) return;
    setError(null);
    if (f.size > MAX_MB * 1024 * 1024) {
      setError(`That file is ${formatBytes(f.size)}. The limit is ${MAX_MB} MB.`);
      return;
    }
    setFile(f);
    if (!title) setTitle(f.name.replace(/\.[^.]+$/, '').slice(0, 120));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return setError('Choose a file first.');
    setError(null);
    setFields({});
    const form = new FormData();
    // Metadata first, then the file: the server reads parts in order.
    form.append('metadata', JSON.stringify({ title, category, claims: claims.filter((c) => c.label.trim() || c.value.trim()) }));
    form.append('file', file);
    setProgress(0);
    try {
      const res = await uploadWithProgress<{ document: { id: string } }>('/api/documents', form, setProgress);
      await queryClient.invalidateQueries({ queryKey: ['documents'] });
      navigate(`/app/documents/${res.document.id}`);
    } catch (err) {
      if (err instanceof ApiError) setFields(err.fields);
      setError(errorMessage(err));
      setProgress(null);
    }
  };

  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader
        back={
          <Link to="/app/documents" className="mb-3 inline-flex items-center gap-1 text-sm font-medium text-accent">
            <ArrowLeft className="size-4" /> My documents
          </Link>
        }
        title="Upload a document"
        description="PDF, PNG or JPEG up to 10 MB. The file is checked, encrypted with its own AES-256 key, and only then stored."
      />
      <form onSubmit={submit} className="space-y-5">
        <Card className="p-4 sm:p-5">
          <button
            type="button"
            onClick={() => input.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              choose(e.dataTransfer.files[0]);
            }}
            className={clsx(
              'flex w-full flex-col items-center rounded-2xl border-2 border-dashed px-4 py-10 text-center transition-colors',
              dragging ? 'border-teal-500 bg-teal-50' : 'border-slate-300 hover:border-accent hover:bg-slate-50',
            )}
          >
            <div className="rounded-2xl bg-accent/10 p-3 text-accent ring-1 ring-inset ring-accent/30 shadow-[0_0_24px_-6px_rgb(var(--glow)/0.5)]">
              <FileUp className="size-6" />
            </div>
            {file ? (
              <>
                <p className="mt-3 font-semibold text-ink">{file.name}</p>
                <p className="text-sm text-slate-500">{formatBytes(file.size)} · tap to choose another</p>
              </>
            ) : (
              <>
                <p className="mt-3 font-semibold text-ink">Tap to choose a file or take a photo</p>
                <p className="text-sm text-slate-500">or drag and drop it here</p>
              </>
            )}
          </button>
          <input ref={input} type="file" accept="application/pdf,image/png,image/jpeg" className="sr-only" onChange={(e) => choose(e.target.files?.[0])} aria-label="Document file" data-testid="file-input" />
        </Card>

        <Card className="space-y-4 p-4 sm:p-5">
          <Field label="Title" htmlFor="title" error={fields.title}>
            <Input id="title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={120} required placeholder="e.g. University enrollment certificate" />
          </Field>
          <Field label="Category" htmlFor="category">
            <Select id="category" value={category} onChange={(e) => setCategory(e.target.value)}>
              {DOCUMENT_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {DOCUMENT_CATEGORY_LABELS[c]}
                </option>
              ))}
            </Select>
          </Field>
        </Card>

        <Card className="space-y-3 p-4 sm:p-5">
          <div>
            <h2 className="font-semibold text-ink">Shareable fields (optional)</h2>
            <p className="mt-0.5 text-sm text-slate-500">
              Add facts from the document, like "Job title: Security Analyst", so you can share one fact without the whole file. These are marked <strong>self-declared</strong> because no issuer signed them.
            </p>
          </div>
          {claims.map((c, i) => (
            <div key={i} className="grid grid-cols-[1fr_1fr_auto] items-center gap-2">
              <Input aria-label={`Field ${i + 1} name`} placeholder="Field" value={c.label} maxLength={60} onChange={(e) => setClaims((cs) => cs.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)))} />
              <Input aria-label={`Field ${i + 1} value`} placeholder="Value" value={c.value} maxLength={200} onChange={(e) => setClaims((cs) => cs.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
              <button type="button" onClick={() => setClaims((cs) => cs.filter((_, j) => j !== i))} className="rounded-lg p-2 text-slate-500 hover:bg-red-50 hover:text-red-400" aria-label={`Remove field ${i + 1}`}>
                <Trash2 className="size-4" />
              </button>
            </div>
          ))}
          <Button variant="secondary" size="sm" icon={<Plus className="size-4" />} onClick={() => setClaims((cs) => [...cs, { label: '', value: '' }])} disabled={claims.length >= 20}>
            Add a field
          </Button>
        </Card>

        <Card className="p-4 sm:p-5">
          <h2 className="flex items-center gap-2 font-semibold text-ink">
            <KeyRound className="size-4 text-teal-400" /> Encryption
          </h2>
          <div role="radiogroup" aria-label="Encryption method" className="mt-3" data-testid="encryption-method">
            <div role="radio" aria-checked="true" aria-disabled="true" className="flex items-start gap-3 rounded-xl bg-accent-soft p-3.5 ring-1 ring-inset ring-accent-line">
              <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-accent" />
              <span>
                <span className="block font-medium text-ink">AES-256-GCM</span>
                <span className="block text-[13px] text-slate-600">256-bit key, authenticated: any change to the stored file is detected.</span>
              </span>
            </div>
          </div>
          <p className="mt-3 text-[13px] leading-relaxed text-slate-500">
            TrustPass uses one method for every file: AES-256-GCM, a widely used standard for authenticated encryption. Offering weaker
            alternatives would only add risk, so there is nothing else to choose. Your file gets its own random key, which is itself
            encrypted before it is stored. After upload, use <strong>Check encryption now</strong> on the document to verify it yourself.
          </p>
        </Card>

        {error && <Alert tone="error">{error}</Alert>}

        {progress !== null && (
          <div className="rounded-xl bg-surface p-4 ring-1 ring-slate-200">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-1.5 font-medium text-ink">
                <Lock className="size-4 text-teal-400" />
                {progress < 1 ? 'Uploading over HTTPS…' : 'Validating and encrypting…'}
              </span>
              <span className="text-slate-500">{Math.round(progress * 100)}%</span>
            </div>
            <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
              <div className="h-full rounded-full bg-teal-500 transition-all" style={{ width: `${Math.max(5, progress * 100)}%` }} />
            </div>
          </div>
        )}

        <Button type="submit" size="lg" className="w-full sm:w-auto" loading={progress !== null} disabled={!file} icon={<Lock className="size-4" />}>
          Encrypt and upload
        </Button>
      </form>
    </div>
  );
}

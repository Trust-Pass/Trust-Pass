import { DOCUMENT_CATEGORY_LABELS, type DocumentCategory } from '@trustpass/shared';
import { useQuery } from '@tanstack/react-query';
import { ChevronRight, FileImage, FileText, GraduationCap, Link2, Lock, Upload } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { ButtonLink, Card, EmptyState, PageHeader, Spinner, Tabs, TrustBadge } from '../components/ui';
import { api } from '../lib/api';
import { formatBytes, formatDate } from '../lib/format';
import type { DocumentSummary } from '../lib/types';

export function DocumentIcon({ doc }: { doc: Pick<DocumentSummary, 'kind' | 'mimeType'> }) {
  if (doc.kind === 'credential') return <GraduationCap className="size-5" />;
  if (doc.mimeType.startsWith('image/')) return <FileImage className="size-5" />;
  return <FileText className="size-5" />;
}

export function DocumentsPage() {
  const [filter, setFilter] = useState<'all' | 'credential' | 'file'>('all');
  const { data, isLoading } = useQuery({ queryKey: ['documents'], queryFn: () => api<{ documents: DocumentSummary[] }>('/api/documents') });
  const docs = data?.documents ?? [];
  const shown = docs.filter((d) => filter === 'all' || d.kind === filter);

  return (
    <div>
      <PageHeader
        title="My documents"
        description="Every file is encrypted with its own key before it is stored. Only you can open the originals."
        actions={
          <>
            <ButtonLink to="/app/credentials" variant="secondary" icon={<GraduationCap className="size-4" />}>
              Get demo credential
            </ButtonLink>
            <ButtonLink to="/app/documents/upload" icon={<Upload className="size-4" />}>
              Upload document
            </ButtonLink>
          </>
        }
      />
      <div className="mb-4">
        <Tabs
          value={filter}
          onChange={setFilter}
          tabs={[
            { value: 'all', label: 'All', count: docs.length },
            { value: 'credential', label: 'Issuer-verified', count: docs.filter((d) => d.kind === 'credential').length },
            { value: 'file', label: 'Uploaded by me', count: docs.filter((d) => d.kind === 'file').length },
          ]}
        />
      </div>
      {isLoading ? (
        <Spinner />
      ) : shown.length === 0 ? (
        <Card>
          <EmptyState
            icon={<FileText className="size-6" />}
            title={docs.length ? 'Nothing in this view' : 'No documents yet'}
            body="Upload a PDF or photo of a certificate, or request a signed demo credential from Demo University."
            action={<ButtonLink to="/app/documents/upload">Upload your first document</ButtonLink>}
          />
        </Card>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2">
          {shown.map((doc) => (
            <li key={doc.id}>
              <Link to={`/app/documents/${doc.id}`} className="block rounded-2xl bg-white p-4 shadow-card ring-1 ring-slate-200/70 transition hover:ring-teal-300">
                <div className="flex items-start gap-3">
                  <div className={doc.kind === 'credential' ? 'rounded-xl bg-teal-50 p-2.5 text-teal-700' : 'rounded-xl bg-navy-50 p-2.5 text-navy-700'}>
                    <DocumentIcon doc={doc} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-2">
                      <p className="line-clamp-2 font-semibold text-navy-950">{doc.title}</p>
                      <ChevronRight className="mt-0.5 size-5 shrink-0 text-slate-400" />
                    </div>
                    <p className="mt-0.5 text-[13px] text-slate-500">
                      {DOCUMENT_CATEGORY_LABELS[doc.category as DocumentCategory] ?? doc.category} · {formatBytes(doc.sizeBytes)} · {formatDate(doc.createdAt)}
                    </p>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <TrustBadge status={doc.trust.status} />
                      <span className="inline-flex items-center gap-1 text-xs text-slate-500">
                        <Lock className="size-3.5" /> Encrypted
                      </span>
                      <span className="inline-flex items-center gap-1 text-xs text-slate-500">
                        <Link2 className="size-3.5" /> {doc.activeLinks} active link{doc.activeLinks === 1 ? '' : 's'}
                      </span>
                    </div>
                  </div>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

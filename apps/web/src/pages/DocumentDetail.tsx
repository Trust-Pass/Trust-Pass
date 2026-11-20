import { DOCUMENT_CATEGORY_LABELS, type DocumentCategory } from '@trustpass/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Download, Eye, KeyRound, Link2, Share2, ShieldCheck, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  CardHeader,
  ConfirmModal,
  EmptyState,
  LinkStatusBadge,
  PageHeader,
  Spinner,
  TrustBadge,
} from '../components/ui';
import { EncryptionCheckPanel } from '../components/EncryptionCheck';
import { LazyPdfViewer } from '../components/LazyPdfViewer';
import { VerificationPanel } from '../components/VerificationPanel';
import { api, apiBlob, errorMessage } from '../lib/api';
import { flag, formatBytes, formatDate, formatDateTime, relativeTime } from '../lib/format';
import type { DocumentDetail } from '../lib/types';

function ImagePreview({ src }: { src: string }) {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let objectUrl: string | null = null;
    apiBlob(src).then((blob) => {
      objectUrl = URL.createObjectURL(blob);
      setUrl(objectUrl);
    });
    return () => {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [src]);
  return url ? <img src={url} alt="Document preview" className="mx-auto max-h-[70vh] rounded-lg shadow-card" /> : <Spinner label="Decrypting" />;
}

export function DocumentDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showPreview, setShowPreview] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { data, isLoading, error } = useQuery({ queryKey: ['document', id], queryFn: () => api<{ document: DocumentDetail }>(`/api/documents/${id}`) });

  const remove = useMutation({
    mutationFn: () => api(`/api/documents/${id}`, { method: 'DELETE' }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['documents'] });
      navigate('/app/documents');
    },
  });

  const downloadCredential = async () => {
    const blob = await apiBlob(`/api/documents/${id}/credential`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'trustpass-credential.sdjwt.txt';
    a.click();
    URL.revokeObjectURL(url);
  };
  const downloadOriginal = async () => {
    const blob = await apiBlob(`/api/documents/${id}/file`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data?.document.mimeType === 'application/pdf' ? 'document.pdf' : 'document';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) return <Spinner />;
  if (error || !data) return <EmptyState icon={<ShieldCheck className="size-6" />} title="Document not found" body={errorMessage(error)} action={<ButtonLink to="/app/documents">Back to documents</ButtonLink>} />;
  const doc = data.document;

  return (
    <div className="space-y-5">
      <PageHeader
        back={
          <Link to="/app/documents" className="mb-3 inline-flex items-center gap-1 text-sm font-medium text-accent">
            <ArrowLeft className="size-4" /> My documents
          </Link>
        }
        title={doc.title}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <TrustBadge status={doc.trust.status} />
            <span>{doc.trust.label}</span>
          </span>
        }
        actions={
          <ButtonLink to={`/app/documents/${doc.id}/share`} variant="teal" icon={<Share2 className="size-4" />}>
            Share document
          </ButtonLink>
        }
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-5">
          {doc.verification && (
            <Card>
              <CardHeader title="Authenticity" subtitle="Re-checked cryptographically every time you open this page." icon={<ShieldCheck className="size-5" />} />
              <div className="p-4 sm:p-5">
                <VerificationPanel verification={doc.verification} />
              </div>
            </Card>
          )}

          <Card>
            <CardHeader
              title="Shareable fields"
              subtitle={doc.kind === 'credential' ? 'Each field is signed by the issuer and can be disclosed on its own.' : 'Fields you entered. Recipients see them as self-declared.'}
            />
            {doc.claims.length === 0 ? (
              <p className="px-5 py-6 text-sm text-slate-500">No fields. You can still share the whole file, view-only and watermarked.</p>
            ) : (
              <dl className="divide-y divide-slate-100">
                {doc.claims.map((c) => (
                  <div key={c.id} className="flex flex-col gap-0.5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
                    <dt className="text-sm text-slate-500">{c.label}</dt>
                    <dd className="flex items-center gap-2 font-medium text-ink">
                      {c.value}
                      {c.source === 'issuer' ? <Badge tone="teal">Signed</Badge> : <Badge tone="amber">Self-declared</Badge>}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </Card>

          <Card>
            <CardHeader
              title="Original file"
              subtitle="Decrypted on the server for you only."
              action={
                <Button size="sm" variant="secondary" icon={<Eye className="size-4" />} onClick={() => setShowPreview((s) => !s)}>
                  {showPreview ? 'Hide' : 'Preview'}
                </Button>
              }
            />
            {showPreview && (
              <div className="bg-slate-100/70 p-3 sm:p-5">
                {doc.mimeType === 'application/pdf' ? <LazyPdfViewer src={`/api/documents/${doc.id}/file`} label={doc.title} /> : <ImagePreview src={`/api/documents/${doc.id}/file`} />}
              </div>
            )}
          </Card>

          <Card>
            <CardHeader title="Shared links" icon={<Link2 className="size-5" />} action={<Link to="/app/links" className="text-sm font-medium text-accent hover:underline">Manage</Link>} />
            {doc.links.length === 0 ? (
              <EmptyState icon={<Share2 className="size-6" />} title="Not shared yet" action={<ButtonLink to={`/app/documents/${doc.id}/share`} size="sm">Create a link</ButtonLink>} />
            ) : (
              <ul className="divide-y divide-slate-100">
                {doc.links.map((l) => (
                  <li key={l.id} className="flex items-center justify-between gap-3 px-4 py-3 sm:px-5">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-ink">{l.recipientOrg ?? l.recipientLabel}</p>
                      <p className="truncate text-xs text-slate-500">
                        {l.claimCount} field{l.claimCount === 1 ? '' : 's'}
                        {l.includeFile && ' + file'} · {l.status === 'active' ? `expires ${relativeTime(l.expiresAt)}` : formatDate(l.expiresAt)} · {l.viewCount} views
                        {l.countries.length > 0 && ` · ${l.countries.map(flag).join(' ')}`}
                      </p>
                    </div>
                    <LinkStatusBadge status={l.status} />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        <aside className="space-y-5">
          <Card className="p-4 sm:p-5">
            <h2 className="flex items-center gap-2 font-semibold text-ink">
              <KeyRound className="size-4 text-teal-400" /> Protection
            </h2>
            <dl className="mt-3 space-y-2.5 text-sm">
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Encryption</dt><dd className="font-medium text-ink">{doc.encryption.algorithm}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Key</dt><dd className="font-medium text-ink">Unique to this file</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Key wrapping</dt><dd className="text-right font-medium text-ink">{doc.encryption.keyWrapping}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Type</dt><dd className="font-medium text-ink">{DOCUMENT_CATEGORY_LABELS[doc.category as DocumentCategory]}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Size</dt><dd className="font-medium text-ink">{formatBytes(doc.sizeBytes)}</dd></div>
              <div className="flex justify-between gap-2"><dt className="text-slate-500">Uploaded</dt><dd className="font-medium text-ink">{formatDateTime(doc.createdAt)}</dd></div>
              <div>
                <dt className="text-slate-500">SHA-256 fingerprint</dt>
                <dd className="mt-1 font-mono text-[11px] break-all text-slate-700">{doc.sha256}</dd>
              </div>
            </dl>
            <EncryptionCheckPanel documentId={doc.id} />
          </Card>

          {doc.credential && (
            <Card className="p-4 sm:p-5">
              <h2 className="font-semibold text-ink">Credential</h2>
              <dl className="mt-3 space-y-2.5 text-sm">
                <div className="flex justify-between gap-2"><dt className="text-slate-500">Issuer</dt><dd className="text-right font-medium text-ink">{doc.credential.issuer}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-slate-500">Format</dt><dd className="font-medium text-ink">{doc.credential.format}</dd></div>
                <div className="flex justify-between gap-2"><dt className="text-slate-500">Valid until</dt><dd className="font-medium text-ink">{formatDate(doc.credential.expiresAt)}</dd></div>
              </dl>
              {doc.credential.simulatedIssuer && <p className="mt-3 rounded-lg bg-amber-50 p-2.5 text-xs text-amber-900">Issued by a simulated university for this demo.</p>}
              <Button variant="secondary" size="sm" className="mt-3 w-full" icon={<Download className="size-4" />} onClick={downloadCredential}>
                Download signed credential
              </Button>
            </Card>
          )}

          <Card className="space-y-2 p-4 sm:p-5">
            <Button variant="secondary" className="w-full" icon={<Download className="size-4" />} onClick={downloadOriginal}>
              Download original
            </Button>
            <Button variant="ghost" className="w-full text-red-400 hover:bg-red-50" icon={<Trash2 className="size-4" />} onClick={() => setConfirmDelete(true)}>
              Delete permanently
            </Button>
          </Card>
        </aside>
      </div>

      <ConfirmModal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => remove.mutate()}
        loading={remove.isPending}
        title="Delete this document?"
        confirmLabel="Delete permanently"
        body={
          <>
            <p>All sharing links stop working immediately. The file's encryption key is destroyed, so TrustPass can no longer decrypt it.</p>
            {remove.error && <p className="mt-2 text-red-400">{errorMessage(remove.error)}</p>}
          </>
        }
      />
    </div>
  );
}

import { useMutation } from '@tanstack/react-query';
import clsx from 'clsx';
import { CheckCircle2, Info, ShieldCheck, XCircle } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { formatBytes, formatDateTime } from '../lib/format';
import type { EncryptionCheck } from '../lib/types';
import { Button } from './ui';

function Row({ ok, label, detail }: { ok: boolean | null; label: string; detail?: string }) {
  return (
    <li className="flex gap-2.5">
      {ok === null ? (
        <Info className="mt-0.5 size-4 shrink-0 text-slate-400" />
      ) : ok ? (
        <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-teal-400" />
      ) : (
        <XCircle className="mt-0.5 size-4 shrink-0 text-red-400" />
      )}
      <span className="min-w-0">
        <span className="block text-ink">{label}</span>
        {detail && <span className="block text-[12px] break-words text-slate-500">{detail}</span>}
      </span>
    </li>
  );
}

/**
 * "Check encryption": asks the server to read this document's stored object, decrypt it and
 * compare it with the fingerprint taken at upload. Read-only; the result says how, never what.
 */
export function EncryptionCheckPanel({ documentId }: { documentId: string }) {
  const check = useMutation({
    mutationFn: () => api<{ check: EncryptionCheck }>(`/api/documents/${documentId}/encryption-check`, { method: 'POST' }),
  });
  const c = check.data?.check;
  return (
    <div className="mt-4 border-t border-slate-200 pt-4" data-testid="encryption-check">
      <Button variant="secondary" size="sm" className="w-full" loading={check.isPending} icon={<ShieldCheck className="size-4" />} onClick={() => check.mutate()}>
        {c ? 'Check again' : 'Check encryption now'}
      </Button>
      {check.error && <p className="mt-2 text-[13px] text-red-400">{errorMessage(check.error)}</p>}
      {c && (
        <div className="mt-3 space-y-3 text-sm">
          <p
            className={clsx('rounded-lg px-3 py-2 text-[13px] font-medium ring-1 ring-inset', c.ok ? 'bg-teal-50 text-teal-900 ring-teal-300' : 'bg-red-50 text-red-900 ring-red-300')}
            data-testid="encryption-check-result"
            data-ok={c.ok}
          >
            {c.ok
              ? 'Verified: the stored file is encrypted and intact.'
              : !c.file.authenticated
                ? 'Problem found: the stored file failed its integrity check. An administrator has been alerted.'
                : 'Not every check passed. See the details below.'}
          </p>
          <ul className="space-y-2">
            <Row ok={!c.file.storedLooksLikePlainFile} label={`Stored as ${c.file.algorithm} ciphertext`} detail={`${formatBytes(c.file.storedBytes)} in storage; the readable file never is.`} />
            <Row ok={c.file.authenticated} label="Authentication tag verified" detail={`${c.file.keyBits}-bit key, ${c.file.ivBytes}-byte IV, ${c.file.tagBytes}-byte tag. Any changed byte would fail this.`} />
            <Row ok={c.file.sha256Matches} label="Matches its fingerprint from upload" detail={c.file.sha256 ?? undefined} />
            <Row ok={c.key.perDocument} label="Its own key, wrapped with AES-256-GCM" detail={`Key protection: ${c.key.providerLabel}.`} />
            <Row ok={c.metadata.titleEncrypted && c.metadata.sha256Encrypted && c.metadata.fieldLabelsEncrypted === c.metadata.fields} label="Title, fingerprint and field names encrypted too" />
            {c.redactedCopyPages > 0 && <Row ok={null} label={`${c.redactedCopyPages} redacted page${c.redactedCopyPages === 1 ? '' : 's'} stored for your links, encrypted with the same key`} />}
          </ul>
          <p className="text-[12px] text-slate-500">Checked {formatDateTime(c.checkedAt)}. Nothing was changed or re-encrypted.</p>
        </div>
      )}
    </div>
  );
}

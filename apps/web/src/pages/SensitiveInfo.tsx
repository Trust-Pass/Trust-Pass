import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { Redaction } from '@trustpass/shared';
import { ArrowLeft, EyeOff } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { RedactionEditor } from '../components/RedactionEditor';
import { Alert, Button, Card, PageHeader, Spinner } from '../components/ui';
import { api, errorMessage } from '../lib/api';
import type { DocumentDetail } from '../lib/types';

/**
 * Choose, for a stored document, what recipients must never see. Saved encrypted with the
 * document's key and applied to every redacted copy shared from now on; the original is untouched.
 */
export function SensitiveInfoPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const doc = useQuery({ queryKey: ['document', id], queryFn: () => api<{ document: DocumentDetail }>(`/api/documents/${id}`) });
  const plan = useQuery({ queryKey: ['redaction-plan', id], queryFn: () => api<{ redactions: Redaction[] }>(`/api/documents/${id}/redaction-plan`) });
  const [boxes, setBoxes] = useState<Redaction[] | null>(null);
  useEffect(() => {
    if (plan.data && boxes === null) setBoxes(plan.data.redactions);
  }, [plan.data, boxes]);
  const save = useMutation({
    mutationFn: () => api(`/api/documents/${id}/redaction-plan`, { method: 'PUT', body: { redactions: boxes ?? [] } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['redaction-plan', id] });
      navigate(`/app/documents/${id}`);
    },
  });

  if (!doc.data || boxes === null) return <Spinner />;
  const d = doc.data.document;
  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader
        back={
          <Link to={`/app/documents/${id}`} className="mb-3 inline-flex items-center gap-1 text-sm font-medium text-accent">
            <ArrowLeft className="size-4" /> {d.title}
          </Link>
        }
        title="Hide sensitive information"
        description="Choose what recipients must never see. Shared copies have it permanently removed; your original stays encrypted and unchanged."
      />
      <Card className="p-4 sm:p-5">
        <RedactionEditor documentId={id} mimeType={d.mimeType} boxes={boxes} onChange={setBoxes} />
      </Card>
      {save.error && (
        <Alert tone="error" className="mt-4">
          {errorMessage(save.error)}
        </Alert>
      )}
      <div className="mt-4 flex flex-wrap gap-3">
        <Button size="lg" icon={<EyeOff className="size-4" />} loading={save.isPending} onClick={() => save.mutate()}>
          Save hidden information
        </Button>
        <Button size="lg" variant="ghost" onClick={() => navigate(`/app/documents/${id}`)}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

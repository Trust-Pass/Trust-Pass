import { DEMO_PROGRAMS } from '@trustpass/shared';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { GraduationCap, KeyRound, Sparkles } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Alert, Button, Card, Field, Input, PageHeader, Select, Spinner } from '../components/ui';
import { api, ApiError, errorMessage } from '../lib/api';
import { useMe } from '../lib/auth';

interface IssuerInfo {
  issuer: { name: string; identifier: string; status: string; simulated: boolean; keyId: string; algorithm: string; format: string };
  held: number;
  limit: number;
}

export function CredentialsPage() {
  const me = useMe();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const latinName = /^[A-Za-z][A-Za-z .'-]*$/.test(me.user.fullName) ? me.user.fullName : '';
  const [name, setName] = useState(latinName);
  const [program, setProgram] = useState<string>(DEMO_PROGRAMS[0]);
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const { data, isLoading } = useQuery({ queryKey: ['issuer'], queryFn: () => api<IssuerInfo>('/api/issuer') });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setFieldError(undefined);
    setLoading(true);
    try {
      const res = await api<{ document: { id: string } }>('/api/issuer/credentials', { body: { nameOnCertificate: name, program } });
      await queryClient.invalidateQueries({ queryKey: ['documents'] });
      await queryClient.invalidateQueries({ queryKey: ['issuer'] });
      navigate(`/app/documents/${res.document.id}`);
    } catch (err) {
      if (err instanceof ApiError) setFieldError(err.fields.nameOnCertificate);
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  if (isLoading || !data) return <Spinner />;
  const full = data.held >= data.limit;

  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader
        title="TrustPass Demo University"
        description="A simulated trusted issuer. It signs real cryptographic credentials so you can try verification and selective sharing end to end."
      />
      <Alert tone="warning" className="mb-5" title="Simulated issuer">
        This university does not exist. TrustPass is not connected to real universities or government systems. The signatures, however, are real Ed25519 signatures.
      </Alert>

      <Card className="overflow-hidden">
        <div className="hero-grid flex items-center gap-3 px-5 py-5 text-white">
          <div className="rounded-2xl bg-white/10 p-3 ring-1 ring-white/20">
            <GraduationCap className="size-7 text-navy-100" />
          </div>
          <div>
            <p className="font-bold">Request an enrollment certificate</p>
            <p className="text-sm text-navy-200">
              You hold {data.held} of {data.limit} demo credentials
            </p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4 p-5">
          <Field label="Name on the certificate" htmlFor="name" error={fieldError} hint="English letters, as on a passport. The PDF certificate uses standard Latin fonts.">
            <Input id="name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} placeholder="e.g. Reham Alkhamees" />
          </Field>
          <Field label="Program" htmlFor="program">
            <Select id="program" value={program} onChange={(e) => setProgram(e.target.value)}>
              {DEMO_PROGRAMS.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </Select>
          </Field>
          {error && <Alert tone="error">{error}</Alert>}
          <Button type="submit" size="lg" variant="teal" className="w-full" loading={loading} disabled={full || data.issuer.status !== 'trusted'} icon={<Sparkles className="size-5" />}>
            Issue my signed credential
          </Button>
          {full && <p className="text-center text-sm text-slate-500">Delete one of your demo credentials to request another.</p>}
        </form>
      </Card>

      <Card className="mt-5 p-5">
        <h2 className="flex items-center gap-2 font-semibold text-ink">
          <KeyRound className="size-4 text-teal-600" /> What you get
        </h2>
        <ul className="mt-3 space-y-2 text-sm text-slate-600">
          <li>• A PDF certificate whose SHA-256 fingerprint is signed by the issuer. Change one byte and it verifies as Invalid.</li>
          <li>• Six signed fields (name, student ID, university, program, status, academic year) you can disclose one at a time.</li>
          <li>
            • Format: {data.issuer.format}, signed with {data.issuer.algorithm}. Key ID <code className="rounded bg-slate-100 px-1 text-xs break-all">{data.issuer.keyId}</code>
          </li>
        </ul>
      </Card>
    </div>
  );
}

import { BarChart3, Clock, FileLock2, Globe2, ListChecks, ShieldCheck, Stamp } from 'lucide-react';
import { Link } from 'react-router';
import { Logo } from '../components/Logo';
import { Seal } from '../components/Seal';
import { ButtonLink } from '../components/ui';
import { useAuth } from '../lib/auth';

const FEATURES = [
  { icon: ListChecks, title: 'Share only what is needed', body: 'Send "Enrollment status: Active" instead of your whole certificate, or a copy with the private parts blacked out for good.' },
  { icon: FileLock2, title: 'Encrypted with AES-256-GCM', body: 'Every file gets its own key. Keys, files and the master key live in three separate places.' },
  { icon: Stamp, title: 'Verify what matters', body: 'Issuer credentials carry an Ed25519 signature. Change one byte and verification fails.' },
  { icon: Clock, title: 'Links that expire', body: '1 hour, 24 hours, 7 days or a date you pick. Revoke any link and it stops working at once.' },
  { icon: Globe2, title: 'Country rules', body: 'Allow Saudi Arabia and the UAE, block the rest. Checked on the server for every request.' },
  { icon: BarChart3, title: 'See every access', body: 'Granted and blocked attempts, approximate countries and alerts, without showing anyone’s IP address.' },
];

const STEPS = [
  { title: 'Upload or receive', body: 'Upload a PDF or photo, or get a signed credential from the demo university.' },
  { title: 'Pick what to show', body: 'Choose the fields, the original file, or a redacted copy with areas you black out.' },
  { title: 'Set the rules', body: 'Recipient, expiry, allowed countries, and whether they may download.' },
  { title: 'Stay in control', body: 'Watch every view arrive. Revoke the link whenever you want.' },
];

const FINE_PRINT = [
  'Location comes from the IP address, so it is approximate. VPNs and mobile networks can change it.',
  'No website can stop screenshots or a phone camera. Watermarks make a leak traceable instead.',
  'The issuing university in this demo is simulated. TrustPass is not connected to real universities or government systems.',
  'Encryption happens on the server. It protects stored files, but it is not end-to-end encryption.',
];

/** A sample of what a recipient sees: two fields shared, two hidden. */
function Specimen() {
  const rows: Array<[string, string | null]> = [
    ['Full name', 'Reham Alkhamees'],
    ['Student number', null],
    ['Enrollment status', 'Active'],
    ['Grade average', null],
  ];
  return (
    <figure className="surface-card relative overflow-hidden rounded-2xl" aria-label="Example of a shared credential">
      <div className="flex items-start justify-between gap-4 px-5 pt-5 sm:px-6">
        <div>
          <p className="text-[13px] text-slate-500">Shared with Example Company</p>
          <p className="mt-0.5 text-lg font-semibold text-ink">Proof of enrollment</p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-800 ring-1 ring-emerald-200">
          <ShieldCheck className="size-3.5" aria-hidden /> Signature valid
        </span>
      </div>
      <dl className="mt-4 divide-y divide-slate-100 border-t border-slate-100">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-4 px-5 py-3 sm:px-6">
            <dt className="text-sm text-slate-500">{label}</dt>
            <dd className="text-sm font-medium text-ink">
              {value ?? (
                <span className="inline-flex items-center gap-2 text-slate-400">
                  <span className="block h-3.5 w-24 rounded-sm bg-ink" aria-hidden />
                  <span className="sr-only">Hidden by the owner</span>
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <div className="perforation mx-5 sm:mx-6" aria-hidden />
      <figcaption className="flex flex-wrap gap-x-5 gap-y-1 px-5 py-4 text-[13px] text-slate-500 sm:px-6">
        <span>Expires in 24 hours</span>
        <span>Watermarked with the recipient’s name</span>
        <span>2 of 4 fields shared</span>
      </figcaption>
    </figure>
  );
}

export function LandingPage() {
  const { me } = useAuth();
  return (
    <div className="min-h-dvh">
      <section className="hero-grid text-white">
        <header className="page-pad mx-auto flex h-16 max-w-6xl items-center justify-between">
          <Logo light />
          <nav className="flex items-center gap-1 sm:gap-2">
            {me ? (
              <ButtonLink to="/app" variant="secondary" size="sm">
                Open dashboard
              </ButtonLink>
            ) : (
              <>
                <Link to="/login" className="rounded-xl px-3 py-2 text-sm font-medium text-navy-100 hover:text-white">
                  Sign in
                </Link>
                <ButtonLink to="/register" variant="secondary" size="sm">
                  Get started
                </ButtonLink>
              </>
            )}
          </nav>
        </header>

        <div className="page-pad mx-auto grid max-w-6xl items-center gap-10 pt-10 pb-36 sm:pt-16 lg:grid-cols-[1fr_auto] lg:pb-40">
          <div>
            <h1 className="max-w-[15ch] text-[40px] leading-[1.04] font-semibold tracking-[-0.035em] sm:text-[64px]">Share the proof, not the whole document.</h1>
            <p className="mt-6 max-w-[34rem] text-lg leading-relaxed text-navy-100">
              Stop sending certificates and IDs over WhatsApp and email. Send exactly the fields someone needs, in a copy that expires, carries their name, and can be taken back.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row sm:items-center">
              <ButtonLink to={me ? '/app' : '/register'} variant="secondary" size="lg">
                {me ? 'Go to dashboard' : 'Create a free account'}
              </ButtonLink>
              {!me && (
                <Link to="/login" className="px-2 py-3 text-[15px] font-medium text-navy-100 underline decoration-navy-400 underline-offset-4 hover:text-white">
                  I already have an account
                </Link>
              )}
            </div>
          </div>
          <div className="hidden lg:block">
            <Seal size={340} draw className="text-navy-200" />
          </div>
        </div>
      </section>

      <div className="page-pad mx-auto -mt-24 max-w-6xl lg:-mt-28">
        <div className="grid items-end gap-8 lg:grid-cols-[minmax(0,26rem)_1fr] lg:gap-14">
          <Specimen />
          <p className="max-w-md pb-2 text-[15px] leading-relaxed text-slate-600">
            This is all Example Company receives. The student number and the grades never leave the server, and the signature proves the rest came from the university unchanged.
          </p>
        </div>
      </div>

      <section className="page-pad mx-auto max-w-6xl py-20 sm:py-28">
        <h2 className="max-w-xl text-[28px] leading-tight font-semibold text-ink sm:text-[34px]">Built for the moments you hand over personal data</h2>
        <p className="mt-3 max-w-2xl text-slate-600">Job applications, admissions, renting an apartment, proving employment. You stay in charge every time.</p>
        <div className="mt-12 grid gap-x-12 gap-y-10 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="border-t border-slate-300 pt-5">
              <Icon className="size-5 text-accent" aria-hidden />
              <h3 className="mt-3 font-semibold text-ink">{title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-600">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="hero-grid py-20 sm:py-24">
        <div className="page-pad mx-auto max-w-6xl">
          <h2 className="text-[28px] leading-tight font-semibold text-white sm:text-[34px]">How it works</h2>
          <ol className="mt-12 grid gap-10 sm:grid-cols-2 lg:grid-cols-4 lg:gap-8">
            {STEPS.map((step, i) => (
              <li key={step.title} className="relative">
                <div className="flex items-center gap-3">
                  <span className="flex size-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold text-navy-950 tabular-nums ring-1 ring-navy-200 bg-navy-100">{i + 1}</span>
                  {i < STEPS.length - 1 && <span className="hidden h-px flex-1 bg-navy-300/40 lg:block" aria-hidden />}
                </div>
                <h3 className="mt-4 font-semibold text-white">{step.title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-navy-200">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="page-pad mx-auto max-w-6xl py-20 sm:py-28">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_1.4fr] lg:gap-16">
          <div>
            <h2 className="text-[28px] leading-tight font-semibold text-ink sm:text-[34px]">The fine print</h2>
            <p className="mt-3 max-w-sm text-slate-600">Security tools earn trust by being clear about their limits. These are ours.</p>
          </div>
          <ul className="divide-y divide-slate-200 border-y border-slate-200">
            {FINE_PRINT.map((line) => (
              <li key={line} className="py-4 text-[15px] leading-relaxed text-slate-700">
                {line}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <footer className="border-t border-slate-200">
        <div className="page-pad mx-auto flex max-w-6xl flex-col gap-3 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <Logo />
          <p>
            Built for a cybersecurity training camp demonstration.{' '}
            <a href="https://db-ip.com" className="underline hover:text-ink" rel="noreferrer noopener" target="_blank">
              IP Geolocation by DB-IP
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}

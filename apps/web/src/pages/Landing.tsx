import { BarChart3, Clock, FileLock2, Globe2, ListChecks, QrCode, ShieldAlert, Stamp } from 'lucide-react';
import { useEffect } from 'react';
import { Link, useLocation } from 'react-router';
import { Logo } from '../components/Logo';
import { Seal } from '../components/Seal';
import { ButtonLink } from '../components/ui';
import { useAuth } from '../lib/auth';

const FEATURES = [
  { icon: ListChecks, title: 'Share only what is needed', body: 'Send "Enrollment status: Active" instead of your whole certificate, or a copy with private parts blacked out for good.' },
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
    <figure
      className="glass w-full max-w-[25rem] overflow-hidden rounded-[22px] ring-1 ring-accent/20 shadow-[0_40px_80px_-30px_rgb(0_0_0/0.9)]"
      aria-label="Example of what a recipient sees"
    >
      <div className="flex items-start justify-between gap-4 px-5 pt-5">
        <div>
          <p className="text-[12.5px] text-slate-500">Shared with Example Company</p>
          <p className="mt-0.5 text-lg font-semibold text-ink">Proof of enrollment</p>
        </div>
        <span className="inline-flex shrink-0 items-center rounded-full bg-accent/10 px-2.5 py-1 text-xs font-medium text-accent ring-1 ring-accent/30">Signature valid</span>
      </div>
      <dl className="mt-4">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between gap-4 border-t border-accent/10 px-5 py-3">
            <dt className="text-sm text-slate-500">{label}</dt>
            <dd className="text-sm font-semibold">
              {value === 'Active' ? (
                <span className="text-glow">{value}</span>
              ) : value ? (
                <span className="text-ink">{value}</span>
              ) : (
                <>
                  <span className="block h-3.5 w-24 rounded-[3px] bg-black ring-1 ring-accent/15" aria-hidden />
                  <span className="sr-only">Hidden by the owner</span>
                </>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <figcaption className="flex flex-wrap gap-x-5 gap-y-1 border-t border-accent/10 px-5 py-3.5 text-[12.5px] text-slate-500">
        <span>Expires in 24 hours</span>
        <span>Watermarked</span>
        <span>2 of 4 fields</span>
      </figcaption>
    </figure>
  );
}

export function LandingPage() {
  const { me } = useAuth();
  const { hash } = useLocation();
  // Links like /#security from the sign-in page land on the right section.
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' });
  }, [hash]);
  return (
    <div className="min-h-dvh overflow-x-clip">
      <header className="page-pad mx-auto flex h-20 max-w-6xl items-center justify-between">
        <Logo />
        <nav className="flex items-center gap-1 sm:gap-2">
          {me ? (
            <ButtonLink to="/app" size="sm">
              Open dashboard
            </ButtonLink>
          ) : (
            <>
              <Link to="/login" className="rounded-xl px-3 py-2 text-sm font-medium text-slate-600 hover:text-ink">
                Sign in
              </Link>
              <ButtonLink to="/register" size="sm">
                Create your vault
              </ButtonLink>
            </>
          )}
        </nav>
      </header>

      <section className="page-pad mx-auto grid max-w-6xl items-center gap-12 pt-6 pb-20 sm:pt-12 lg:grid-cols-[1.05fr_1fr] lg:pb-28">
        <div>
          <h1 className="max-w-[13ch] text-[44px] leading-[1.0] font-semibold tracking-[-0.045em] text-ink sm:text-[72px]">
            Share the proof, <span className="text-gradient">not the whole document.</span>
          </h1>
          <p className="mt-6 max-w-[33rem] text-lg leading-relaxed text-slate-600">
            Send exactly the fields someone needs, in a copy that expires, carries their name, and can be taken back. Everything else stays encrypted.
          </p>
          <div className="mt-9 flex flex-col gap-3 sm:flex-row">
            <ButtonLink to={me ? '/app' : '/register'} size="lg">
              {me ? 'Go to dashboard' : 'Create a free account'}
            </ButtonLink>
            <ButtonLink to={me ? '/app/scan' : '/login'} variant="secondary" size="lg">
              {me ? 'Check a QR code' : 'I already have an account'}
            </ButtonLink>
          </div>
          <dl className="mt-12 grid max-w-xl grid-cols-3 gap-4 border-t border-accent/10 pt-6">
            {[
              ['AES-256-GCM', 'a key for every file'],
              ['Ed25519', 'signed credentials'],
              ['Redacted copies', 'hidden parts burned out'],
            ].map(([term, detail]) => (
              <div key={term}>
                <dt className="text-[15px] font-semibold text-ink">{term}</dt>
                <dd className="mt-0.5 text-[13px] text-slate-500">{detail}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="relative grid min-h-[22rem] place-items-center sm:min-h-[30rem]">
          <div className="absolute inset-0 grid place-items-center" aria-hidden>
            <Seal size={500} draw emblem={false} className="max-w-full text-accent opacity-90 drop-shadow-[0_0_34px_rgb(34_227_208/0.45)]" />
          </div>
          <div className="relative z-10 w-full max-w-[25rem]">
            <Specimen />
          </div>
        </div>
      </section>

      <section id="features" className="page-pad mx-auto max-w-6xl scroll-mt-6 py-16 sm:py-24">
        <h2 className="max-w-xl text-[28px] leading-tight font-semibold text-ink sm:text-[36px]">Built for the moments you hand over personal data</h2>
        <p className="mt-3 max-w-2xl text-slate-500">Job applications, admissions, renting an apartment, proving employment. You stay in charge every time.</p>
        <div className="mt-12 grid gap-x-12 gap-y-10 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="border-t border-accent/15 pt-5">
              <Icon className="size-5 text-accent drop-shadow-[0_0_8px_rgb(34_227_208/0.6)]" aria-hidden />
              <h3 className="mt-3 font-semibold text-ink">{title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-500">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="page-pad mx-auto max-w-6xl">
        <div className="surface-card card-lit rounded-[28px] px-6 py-12 sm:px-12 sm:py-14">
          <h2 className="text-[28px] leading-tight font-semibold text-ink sm:text-[36px]">How it works</h2>
          <ol className="mt-10 grid gap-10 sm:grid-cols-2 lg:grid-cols-4 lg:gap-8">
            {STEPS.map((step, i) => (
              <li key={step.title}>
                <div className="flex items-center gap-3">
                  <span className="num flex size-9 shrink-0 items-center justify-center rounded-full bg-accent/10 text-sm font-semibold text-accent ring-1 ring-accent/40">{i + 1}</span>
                  {i < STEPS.length - 1 && <span className="hidden h-px flex-1 bg-gradient-to-r from-accent/40 to-transparent lg:block" aria-hidden />}
                </div>
                <h3 className="mt-4 font-semibold text-ink">{step.title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-slate-500">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* QR Security: the crimson zone, introduced where it lives. */}
      <section id="security" className="page-pad mx-auto max-w-6xl scroll-mt-6 py-16 sm:py-24">
        <div className="zone-threat surface-card card-lit relative overflow-hidden rounded-[28px] px-6 py-10 sm:px-12 sm:py-12">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(40rem_20rem_at_90%_0%,rgb(225_29_72/0.25),transparent_60%)]" aria-hidden />
          <div className="relative grid items-center gap-8 lg:grid-cols-[1.2fr_1fr]">
            <div>
              <p className="inline-flex items-center gap-2 text-sm font-medium text-accent">
                <ShieldAlert className="size-4" aria-hidden /> QR Security
              </p>
              <h2 className="mt-3 text-[28px] leading-tight font-semibold text-ink sm:text-[36px]">Check a QR code before it opens anything</h2>
              <p className="mt-3 max-w-xl text-slate-500">
                The code is read on your phone and checked for phishing tricks: look-alike brands, hidden addresses, shorteners and app installs. Nothing is opened until you choose to.
              </p>
            </div>
            <div className="flex lg:justify-end">
              <ButtonLink to={me ? '/app/scan' : '/register'} size="lg" icon={<QrCode className="size-5" />}>
                {me ? 'Open QR Security' : 'Try QR Security'}
              </ButtonLink>
            </div>
          </div>
        </div>
      </section>

      <section id="about" className="page-pad mx-auto max-w-6xl scroll-mt-6 pb-20 sm:pb-28">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_1.4fr] lg:gap-16">
          <div>
            <h2 className="text-[28px] leading-tight font-semibold text-ink sm:text-[36px]">The fine print</h2>
            <p className="mt-3 max-w-sm text-slate-500">Security tools earn trust by being clear about their limits. These are ours.</p>
          </div>
          <ul className="divide-y divide-accent/10 border-y border-accent/10">
            {FINE_PRINT.map((line) => (
              <li key={line} className="py-4 text-[15px] leading-relaxed text-slate-600">
                {line}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <footer className="border-t border-accent/10">
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

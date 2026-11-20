import { Clock, FileLock2, ListChecks, QrCode, ShieldAlert, Stamp } from 'lucide-react';
import { useEffect } from 'react';
import { Link, useLocation } from 'react-router';
import { Logo } from '../components/Logo';
import { Seal } from '../components/Seal';
import { ButtonLink } from '../components/ui';
import { useAuth } from '../lib/auth';

const FEATURES = [
  { icon: ListChecks, title: 'Share only what is needed', body: 'Single fields, or a copy with phone numbers, salaries and other private parts burned out.' },
  { icon: FileLock2, title: 'Encrypted with AES-256-GCM', body: 'Every file has its own key. Check its encryption yourself at any time.' },
  { icon: Clock, title: 'You set the rules', body: 'Recipient, expiry, countries, downloads and watermark. Revoke a link at once.' },
  { icon: Stamp, title: 'Verifiable credentials', body: 'Ed25519 signatures: change one byte and verification fails.' },
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
  // Links like /#security land on the right section.
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

      <section className="page-pad mx-auto grid max-w-6xl items-center gap-10 pt-4 pb-12 sm:pt-10 lg:grid-cols-[1.05fr_1fr] lg:pb-16">
        <div>
          <h1 className="max-w-[13ch] text-[44px] leading-[1.0] font-semibold tracking-[-0.045em] text-ink sm:text-[72px]">
            Share the proof, <span className="text-gradient">not the whole document.</span>
          </h1>
          <p className="mt-6 max-w-[33rem] text-lg leading-relaxed text-slate-600">
            Share exactly what someone needs, in a copy that expires and can be taken back. Everything else stays encrypted.
          </p>
          <div className="mt-9 flex flex-col gap-3 sm:flex-row">
            <ButtonLink to={me ? '/app' : '/register'} size="lg">
              {me ? 'Go to dashboard' : 'Create a free account'}
            </ButtonLink>
            <ButtonLink to={me ? '/app/scan' : '/login'} variant="secondary" size="lg">
              {me ? 'Check a QR code' : 'I already have an account'}
            </ButtonLink>
          </div>
        </div>
        <div className="relative grid min-h-[20rem] place-items-center sm:min-h-[28rem]">
          <div className="absolute inset-0 grid place-items-center" aria-hidden>
            <Seal size={440} draw emblem={false} className="max-w-full text-accent opacity-90 drop-shadow-[0_0_34px_rgb(34_227_208/0.45)]" />
          </div>
          <div className="relative z-10 w-full max-w-[25rem]">
            <Specimen />
          </div>
        </div>
      </section>

      <section id="features" className="page-pad mx-auto max-w-6xl scroll-mt-6 py-10 sm:py-14">
        <div className="grid gap-x-10 gap-y-7 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="border-t border-accent/15 pt-4">
              <Icon className="size-5 text-accent drop-shadow-[0_0_8px_rgb(34_227_208/0.6)]" aria-hidden />
              <h2 className="mt-3 font-semibold text-ink">{title}</h2>
              <p className="mt-1 text-sm leading-relaxed text-slate-500">{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* QR Security: the crimson zone, introduced where it lives. */}
      <section id="security" className="page-pad mx-auto max-w-6xl scroll-mt-6 pt-4 pb-14 sm:pb-20">
        <div className="zone-threat surface-card card-lit relative overflow-hidden rounded-[28px] px-6 py-8 sm:px-10 sm:py-10">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(40rem_20rem_at_90%_0%,rgb(225_29_72/0.25),transparent_60%)]" aria-hidden />
          <div className="relative grid items-center gap-8 lg:grid-cols-[1.2fr_1fr]">
            <div>
              <p className="inline-flex items-center gap-2 text-sm font-medium text-accent">
                <ShieldAlert className="size-4" aria-hidden /> QR Security
              </p>
              <h2 className="mt-2 text-[24px] leading-tight font-semibold text-ink sm:text-[30px]">Check a QR code before it opens anything</h2>
              <p className="mt-2 max-w-xl text-slate-500">Spots phishing links, look-alike brands and unsafe destinations. Nothing opens until you choose.</p>
            </div>
            <div className="flex lg:justify-end">
              <ButtonLink to={me ? '/app/scan' : '/register'} size="lg" icon={<QrCode className="size-5" />}>
                {me ? 'Open QR Security' : 'Try QR Security'}
              </ButtonLink>
            </div>
          </div>
        </div>
      </section>

      <footer className="border-t border-accent/10">
        <div className="page-pad mx-auto flex max-w-6xl flex-col gap-3 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <Logo />
          <p className="max-w-xl">
            A cybersecurity training camp demonstration. Encryption is server-side, not end-to-end; locations are approximate; the demo issuer is simulated.{' '}
            <a href="https://db-ip.com" className="underline hover:text-ink" rel="noreferrer noopener" target="_blank">
              IP Geolocation by DB-IP
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}

import {
  ArrowRight,
  BarChart3,
  Clock,
  EyeOff,
  FileLock2,
  Fingerprint,
  Globe2,
  ListChecks,
  ShieldCheck,
  Stamp,
} from 'lucide-react';
import { Link } from 'react-router';
import { Logo } from '../components/Logo';
import { ButtonLink } from '../components/ui';
import { useAuth } from '../lib/auth';

const FEATURES = [
  { icon: FileLock2, title: 'Encrypted with AES-256-GCM', body: 'Every file gets its own key. Keys, files and the master key live in three separate places.' },
  { icon: ListChecks, title: 'Share only what is needed', body: 'Send "enrollment status: Active" instead of your whole certificate. Hidden fields never leave the server.' },
  { icon: Stamp, title: 'Verify what matters', body: 'Issuer credentials carry an Ed25519 signature. Change one byte and verification fails.' },
  { icon: Clock, title: 'Links that expire', body: '1 hour, 24 hours, 7 days or a date you pick. Revoke any link and it stops working instantly.' },
  { icon: Globe2, title: 'Country rules', body: 'Allow Saudi Arabia and the UAE, block the rest. Checked on the server for every request.' },
  { icon: BarChart3, title: 'See every access', body: 'Granted and blocked attempts, approximate countries and alerts, without exposing anyone’s IP address.' },
];

const STEPS = [
  { title: 'Upload or receive', body: 'Upload a PDF or photo, or get a signed credential from the demo university.' },
  { title: 'Pick the fields', body: 'Choose exactly what the recipient may see, and whether the file itself is included.' },
  { title: 'Set the rules', body: 'Recipient, expiry and allowed countries. TrustPass creates a unique secure link.' },
  { title: 'Stay in control', body: 'Watch views arrive in your analytics. Revoke whenever you want.' },
];

const HONEST = [
  'Location comes from the IP address, so it is approximate. VPNs and mobile networks can change it.',
  'No website can stop screenshots or a phone camera. Watermarks make a leak traceable instead.',
  'The issuing university in this demo is simulated. TrustPass is not connected to real universities or government systems.',
  'Encryption happens on the server. It protects stored files, but it is not end-to-end encryption.',
];

export function LandingPage() {
  const { me } = useAuth();
  return (
    <div className="min-h-dvh">
      <section className="hero-grid text-white">
        <header className="page-pad mx-auto flex h-16 max-w-6xl items-center justify-between">
          <Logo light />
          <nav className="flex items-center gap-2">
            {me ? (
              <ButtonLink to="/app" variant="teal" size="sm">
                Open dashboard
              </ButtonLink>
            ) : (
              <>
                <Link to="/login" className="rounded-xl px-3 py-2 text-sm font-medium text-navy-100 hover:text-white">
                  Sign in
                </Link>
                <ButtonLink to="/register" variant="teal" size="sm">
                  Get started
                </ButtonLink>
              </>
            )}
          </nav>
        </header>

        <div className="page-pad mx-auto max-w-6xl pt-12 pb-20 sm:pt-20 sm:pb-28">
          <p className="inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-sm text-teal-300 ring-1 ring-white/15">
            <ShieldCheck className="size-4" /> Secure document sharing and verification
          </p>
          <h1 className="mt-5 max-w-3xl text-4xl leading-[1.1] font-extrabold tracking-tight sm:text-6xl">
            Your documents.
            <br />
            <span className="bg-gradient-to-r from-teal-300 via-sky-300 to-blue-400 bg-clip-text text-transparent">Your control.</span>
          </h1>
          <p className="mt-5 max-w-xl text-lg text-navy-100">
            Stop sending certificates and IDs over WhatsApp and email. Share only what is necessary, verify what matters, and stay in control after you hit send.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <ButtonLink to={me ? '/app' : '/register'} variant="teal" size="lg" icon={<ArrowRight className="size-5" />}>
              {me ? 'Go to dashboard' : 'Create a free account'}
            </ButtonLink>
            <ButtonLink to="/login" variant="secondary" size="lg" className="bg-white/10 text-white ring-white/25 hover:bg-white/15">
              I already have an account
            </ButtonLink>
          </div>

          <div className="mt-14 grid max-w-3xl grid-cols-3 gap-3 text-center sm:gap-6">
            {[
              ['AES-256', 'encryption at rest'],
              ['Ed25519', 'signed credentials'],
              ['0', 'full IPs shown to owners'],
            ].map(([big, small]) => (
              <div key={big} className="rounded-2xl bg-white/5 px-2 py-4 ring-1 ring-white/10">
                <p className="text-xl font-bold text-white sm:text-2xl">{big}</p>
                <p className="mt-1 text-xs text-navy-200 sm:text-sm">{small}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="page-pad mx-auto max-w-6xl py-16 sm:py-24">
        <h2 className="text-gradient text-2xl font-bold tracking-tight sm:text-3xl">Built for the moments you hand over personal data</h2>
        <p className="mt-2 max-w-2xl text-slate-600">Job applications, admissions, renting an apartment, proving employment. TrustPass keeps the owner in charge every time.</p>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="surface-card group rounded-2xl p-5 transition duration-200 hover:-translate-y-0.5 hover:border-blue-400/30">
              <div className="inline-flex rounded-xl bg-gradient-to-br from-blue-500/25 to-teal-400/10 p-2.5 text-teal-300 ring-1 ring-inset ring-white/10 transition group-hover:text-teal-300">
                <Icon className="size-5" />
              </div>
              <h3 className="mt-4 font-semibold text-ink">{title}</h3>
              <p className="mt-1.5 text-sm leading-relaxed text-slate-600">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-y border-white/[0.06] bg-gradient-to-b from-blue-950/40 to-transparent py-16 sm:py-24">
        <div className="page-pad mx-auto max-w-6xl">
          <h2 className="text-gradient text-2xl font-bold tracking-tight sm:text-3xl">How it works</h2>
          <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((step, i) => (
              <li key={step.title} className="surface-card rounded-2xl p-5">
                <span className="flex size-8 items-center justify-center rounded-full bg-gradient-to-br from-teal-300 to-blue-500 text-sm font-bold text-navy-950 shadow-glow-teal">{i + 1}</span>
                <h3 className="mt-3 font-semibold text-ink">{step.title}</h3>
                <p className="mt-1 text-sm text-slate-600">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="page-pad mx-auto max-w-6xl py-16 sm:py-24">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2 lg:gap-14">
          <div>
            <div className="inline-flex rounded-xl bg-amber-100 p-2.5 text-amber-700">
              <EyeOff className="size-5" />
            </div>
            <h2 className="mt-4 text-gradient text-2xl font-bold tracking-tight sm:text-3xl">What we will not pretend</h2>
            <p className="mt-2 text-slate-600">Security tools earn trust by being clear about their limits. These are ours.</p>
          </div>
          <ul className="space-y-3">
            {HONEST.map((line) => (
              <li key={line} className="flex gap-3 rounded-xl bg-slate-50 p-4 text-sm leading-relaxed text-slate-700 ring-1 ring-slate-200/80">
                <Fingerprint className="mt-0.5 size-4 shrink-0 text-accent" />
                {line}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <footer className="border-t border-white/[0.06]">
        <div className="page-pad mx-auto flex max-w-6xl flex-col gap-3 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <Logo />
          <p>
            Built for a cybersecurity training camp demonstration. <a href="https://db-ip.com" className="underline hover:text-ink" rel="noreferrer noopener" target="_blank">IP Geolocation by DB-IP</a>
          </p>
        </div>
      </footer>
    </div>
  );
}

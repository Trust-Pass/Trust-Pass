/**
 * Creates the administrator account (from ADMIN_EMAIL / ADMIN_PASSWORD) and
 * registers the demo issuer. Safe to run repeatedly.
 *
 *   pnpm db:seed
 */
import { PrismaClient } from '@prisma/client';
import { emailSchema, passwordSchema } from '@trustpass/shared';
import { loadConfig } from '../config';
import { hashPassword } from '../modules/auth';
import { ensureDemoIssuer } from '../services/issuer';
import { createGeoProvider } from '../lib/geo';
import { createStorage } from '../lib/storage';
import type { AppDeps } from '../types';

async function main() {
  const config = loadConfig();
  const prisma = new PrismaClient();
  const deps: AppDeps = {
    config,
    prisma,
    storage: createStorage(config, prisma),
    geo: await createGeoProvider(config),
    mailer: { transport: 'none', send: async () => undefined },
    now: () => new Date(),
  };

  const issuer = await ensureDemoIssuer(deps);
  console.log(`Demo issuer ready: ${issuer.name} (key ${issuer.kid.slice(0, 12)}...)`);

  const { ADMIN_EMAIL, ADMIN_PASSWORD } = config.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const email = emailSchema.parse(ADMIN_EMAIL);
    const password = passwordSchema.parse(ADMIN_PASSWORD);
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      if (existing.role !== 'admin') await prisma.user.update({ where: { id: existing.id }, data: { role: 'admin' } });
      console.log(`Administrator exists: ${email}`);
    } else {
      await prisma.user.create({
        data: { email, passwordHash: await hashPassword(password), fullName: 'TrustPass Administrator', accountType: 'individual', role: 'admin' },
      });
      console.log(`Administrator created: ${email}`);
    }
  } else {
    console.log('ADMIN_EMAIL / ADMIN_PASSWORD not set: no administrator created');
  }
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});

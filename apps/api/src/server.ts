import { PrismaClient } from '@prisma/client';
import { buildApp } from './app';
import { loadConfig } from './config';
import { ensureDemoIssuer } from './services/issuer';
import { runRetention } from './services/retention';

const SIX_HOURS = 6 * 60 * 60 * 1000;

async function main() {
  const config = loadConfig();
  const prisma = new PrismaClient();
  const app = await buildApp({ config, prisma });

  await ensureDemoIssuer(app.deps);

  const timer = setInterval(() => {
    runRetention(app.deps).catch((err) => app.log.error({ err }, 'retention job failed'));
  }, SIX_HOURS);
  timer.unref();

  const shutdown = async (signal: string) => {
    app.log.info(`${signal} received, shutting down`);
    clearInterval(timer);
    await app.close();
    await prisma.$disconnect();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.env.HOST, port: config.env.PORT });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});

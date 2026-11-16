import type { AppDeps } from '../types';
import { logEvent } from './audit';
import { getSettings } from './settings';

const SECURITY_EVENT_RETENTION_DAYS = 365;

/**
 * Deletes access logs (which hold approximate location) after the configured
 * retention period, plus old sessions, reset tokens and security events. The
 * audit tables reject deletes unless this transaction enables the purge flag.
 */
export async function runRetention(deps: AppDeps, actorUserId: string | null = null) {
  const { prisma, now } = deps;
  const settings = await getSettings(prisma);
  const current = now();
  const accessCutoff = new Date(current.getTime() - settings.logRetentionDays * 24 * 60 * 60 * 1000);
  const eventCutoff = new Date(current.getTime() - SECURITY_EVENT_RETENTION_DAYS * 24 * 60 * 60 * 1000);

  const [accessLogs, securityEvents] = await prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('trustpass.allow_log_purge', 'on', true)`;
    const a = await tx.accessLog.deleteMany({ where: { createdAt: { lt: accessCutoff } } });
    const e = await tx.securityEvent.deleteMany({ where: { createdAt: { lt: eventCutoff } } });
    return [a.count, e.count];
  });
  const sessions = await prisma.session.deleteMany({ where: { expiresAt: { lt: current } } });
  const resets = await prisma.passwordResetToken.deleteMany({ where: { expiresAt: { lt: current } } });

  const result = {
    accessLogsDeleted: accessLogs,
    securityEventsDeleted: securityEvents,
    expiredSessionsDeleted: sessions.count,
    expiredResetTokensDeleted: resets.count,
    accessLogRetentionDays: settings.logRetentionDays,
  };
  await logEvent(prisma, { actorUserId, eventType: 'log_retention_run', metadata: result });
  return result;
}

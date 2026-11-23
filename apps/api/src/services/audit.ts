import type { Prisma, PrismaClient, Severity } from '@prisma/client';

type Db = PrismaClient | Prisma.TransactionClient;

export interface SecurityEventInput {
  userId?: string | null;
  actorUserId?: string | null;
  eventType: string;
  severity?: Severity;
  documentId?: string | null;
  linkId?: string | null;
  /** Never put document contents, tokens or full IP addresses here. */
  metadata?: Record<string, unknown>;
  at?: Date;
}

export async function logEvent(db: Db, event: SecurityEventInput): Promise<void> {
  await db.securityEvent.create({
    data: {
      userId: event.userId ?? null,
      actorUserId: event.actorUserId ?? null,
      eventType: event.eventType,
      severity: event.severity ?? 'info',
      documentId: event.documentId ?? null,
      linkId: event.linkId ?? null,
      metadata: (event.metadata ?? {}) as Prisma.InputJsonValue,
      ...(event.at ? { createdAt: event.at } : {}),
    },
  });
}

export interface NotificationInput {
  userId: string;
  type: string;
  title: string;
  body: string;
  linkId?: string | null;
  documentId?: string | null;
  at?: Date;
}

export async function notify(db: Db, input: NotificationInput): Promise<void> {
  await db.notification.create({
    data: {
      userId: input.userId,
      type: input.type,
      title: input.title.slice(0, 160),
      body: input.body.slice(0, 500),
      linkId: input.linkId ?? null,
      documentId: input.documentId ?? null,
      ...(input.at ? { createdAt: input.at } : {}),
    },
  });
}

/**
 * Notifications are for security alerts only. The bell shows exactly two kinds:
 *  - repeated blocked attempts on one link (alert_denied_burst)
 *  - an attempt to open a link after it expired (alert_expired_link; older records of this kind
 *    were stored as alert_after_end with "expired" in their title)
 * Other security records (first view from a new country, revoked-link attempts, account lock,
 * integrity alerts) are still stored and still feed the Security alerts card on Analytics and the
 * security events log, but they are not shown as notifications.
 */
export type SecurityNotificationKind = 'repeated_attempts' | 'expired_link';

export const SECURITY_NOTIFICATION_TEXT: Record<SecurityNotificationKind, { title: string; description: string }> = {
  repeated_attempts: { title: 'Repeated access attempts', description: 'Someone tried to access your document multiple times.' },
  expired_link: { title: 'Expired link access blocked', description: 'Someone tried to open your document after the link expired. Access was blocked.' },
};

export function securityNotificationWhere(userId: string) {
  return {
    userId,
    OR: [
      { type: 'alert_denied_burst' },
      { type: 'alert_expired_link' },
      { type: 'alert_after_end', title: { contains: 'expired' } },
    ],
  };
}

export function securityNotificationKind(type: string): SecurityNotificationKind {
  return type === 'alert_denied_burst' ? 'repeated_attempts' : 'expired_link';
}

/** Avoid flooding: true when the same notification type was sent for this link recently. */
export async function recentlyNotified(db: Db, userId: string, type: string, linkId: string, since: Date): Promise<boolean> {
  const count = await db.notification.count({ where: { userId, type, linkId, createdAt: { gte: since } } });
  return count > 0;
}

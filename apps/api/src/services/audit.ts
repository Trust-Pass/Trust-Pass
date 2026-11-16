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

/** Avoid flooding: true when the same notification type was sent for this link recently. */
export async function recentlyNotified(db: Db, userId: string, type: string, linkId: string, since: Date): Promise<boolean> {
  const count = await db.notification.count({ where: { userId, type, linkId, createdAt: { gte: since } } });
  return count > 0;
}

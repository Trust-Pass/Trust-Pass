import type { Prisma, PrismaClient } from '@prisma/client';
import { DEFAULT_SETTINGS, updateSettingsSchema, type SystemSettings } from '@trustpass/shared';

const KEY = 'platform';

export async function getSettings(prisma: PrismaClient): Promise<SystemSettings> {
  const row = await prisma.systemSetting.findUnique({ where: { key: KEY } });
  const merged = { ...DEFAULT_SETTINGS, ...((row?.value as Partial<SystemSettings> | undefined) ?? {}) };
  const parsed = updateSettingsSchema.safeParse(merged);
  return parsed.success ? parsed.data : DEFAULT_SETTINGS;
}

export async function saveSettings(prisma: PrismaClient, value: SystemSettings, userId: string): Promise<void> {
  await prisma.systemSetting.upsert({
    where: { key: KEY },
    create: { key: KEY, value: value as unknown as Prisma.InputJsonValue, updatedById: userId },
    update: { value: value as unknown as Prisma.InputJsonValue, updatedById: userId },
  });
}

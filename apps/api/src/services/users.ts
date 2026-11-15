import type { PrismaClient, User } from '@prisma/client';

/** The only user fields ever sent to the browser. */
export function publicUser(user: User) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    accountType: user.accountType,
    role: user.role,
    createdAt: user.createdAt,
  };
}

export async function userOrganizations(prisma: PrismaClient, userId: string) {
  const memberships = await prisma.organizationMember.findMany({
    where: { userId, organization: { status: 'active' } },
    include: { organization: true },
    orderBy: { createdAt: 'asc' },
  });
  return memberships.map((m) => ({
    id: m.organization.id,
    name: m.organization.name,
    slug: m.organization.slug,
    type: m.organization.type,
    role: m.role,
  }));
}

/** Organization ids where the user is an active member. */
export async function memberOrgIds(prisma: PrismaClient, userId: string): Promise<string[]> {
  const rows = await prisma.organizationMember.findMany({
    where: { userId, organization: { status: 'active' } },
    select: { orgId: true },
  });
  return rows.map((r) => r.orgId);
}

import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { OrgRole } from '@prisma/client';
import { addMemberSchema, updateMemberSchema } from '@trustpass/shared';
import { z } from 'zod';
import { AppError, forbidden, notFound, parse } from '../lib/errors';
import { requireUser } from '../plugins/auth';
import { logEvent, notify } from '../services/audit';

const orgParams = z.object({ orgId: z.string().uuid() });
const memberParams = z.object({ orgId: z.string().uuid(), userId: z.string().uuid() });

export async function organizationRoutes(app: FastifyInstance) {
  const { prisma } = app.deps;

  /** Returns the caller's membership; non-members get 404 so organizations cannot be probed. */
  async function membership(request: FastifyRequest, orgId: string, roles?: OrgRole[]) {
    const { user } = requireUser(request);
    const member = await prisma.organizationMember.findUnique({
      where: { orgId_userId: { orgId, userId: user.id } },
      include: { organization: true },
    });
    if (!member || member.organization.status !== 'active') throw notFound('Organization');
    if (roles && !roles.includes(member.role)) throw forbidden('Only organization owners or admins can do this');
    return { user, member };
  }

  app.get('/api/organizations/directory', async (request) => {
    requireUser(request);
    const { q } = z.object({ q: z.string().trim().max(60).default('') }).parse(request.query);
    const orgs = await prisma.organization.findMany({
      where: { status: 'active', ...(q ? { name: { contains: q, mode: 'insensitive' as const } } : {}) },
      select: { id: true, name: true, type: true },
      orderBy: { name: 'asc' },
      take: 20,
    });
    return { organizations: orgs };
  });

  app.get('/api/organizations/:orgId', async (request) => {
    const { orgId } = orgParams.parse(request.params);
    const { member } = await membership(request, orgId);
    const [members, received, verifications] = await Promise.all([
      prisma.organizationMember.findMany({
        where: { orgId },
        include: { user: { select: { id: true, fullName: true, email: true } } },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.sharingLink.count({ where: { recipientOrgId: orgId } }),
      prisma.verificationRecord.groupBy({ by: ['result'], where: { verifiedByOrgId: orgId }, _count: { _all: true } }),
    ]);
    return {
      organization: {
        id: member.organization.id,
        name: member.organization.name,
        type: member.organization.type,
        slug: member.organization.slug,
        createdAt: member.organization.createdAt,
      },
      myRole: member.role,
      members: members.map((m) => ({ userId: m.user.id, fullName: m.user.fullName, email: m.user.email, role: m.role, since: m.createdAt })),
      stats: {
        receivedLinks: received,
        verifications: Object.fromEntries(verifications.map((v) => [v.result, v._count._all])),
      },
    };
  });

  app.post('/api/organizations/:orgId/members', async (request, reply) => {
    const { orgId } = orgParams.parse(request.params);
    const { user, member } = await membership(request, orgId, ['owner', 'admin']);
    const input = parse(addMemberSchema, request.body);
    const target = await prisma.user.findUnique({ where: { email: input.email } });
    if (!target || target.status !== 'active') {
      throw new AppError(404, 'user_not_found', 'No active TrustPass account uses that email. Ask them to register first.');
    }
    const exists = await prisma.organizationMember.findUnique({ where: { orgId_userId: { orgId, userId: target.id } } });
    if (exists) throw new AppError(409, 'already_member', 'That person is already a member');
    await prisma.organizationMember.create({ data: { orgId, userId: target.id, role: input.role } });
    await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'org_member_added', metadata: { orgId, member: target.email, role: input.role } });
    await notify(prisma, {
      userId: target.id,
      type: 'org_member_added',
      title: `You joined ${member.organization.name}`,
      body: `${user.fullName} added you to ${member.organization.name} as ${input.role}. Documents shared with the organization now appear in your organization dashboard.`,
    });
    return reply.status(201).send({ ok: true });
  });

  app.patch('/api/organizations/:orgId/members/:userId', async (request) => {
    const params = memberParams.parse(request.params);
    const { user } = await membership(request, params.orgId, ['owner']);
    const input = parse(updateMemberSchema, request.body);
    const target = await prisma.organizationMember.findUnique({ where: { orgId_userId: { orgId: params.orgId, userId: params.userId } } });
    if (!target) throw notFound('Member');
    if (target.role === 'owner' && input.role !== 'owner') {
      const owners = await prisma.organizationMember.count({ where: { orgId: params.orgId, role: 'owner' } });
      if (owners <= 1) throw new AppError(409, 'last_owner', 'An organization needs at least one owner');
    }
    await prisma.organizationMember.update({ where: { orgId_userId: { orgId: params.orgId, userId: params.userId } }, data: { role: input.role } });
    await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'org_member_role_changed', metadata: { orgId: params.orgId, member: params.userId, role: input.role } });
    return { ok: true };
  });

  app.delete('/api/organizations/:orgId/members/:userId', async (request) => {
    const params = memberParams.parse(request.params);
    const { user, member } = await membership(request, params.orgId);
    const removingSelf = params.userId === user.id;
    if (!removingSelf && !['owner', 'admin'].includes(member.role)) throw forbidden('Only organization owners or admins can remove members');
    const target = await prisma.organizationMember.findUnique({ where: { orgId_userId: { orgId: params.orgId, userId: params.userId } } });
    if (!target) throw notFound('Member');
    if (target.role === 'owner') {
      if (member.role !== 'owner' && !removingSelf) throw forbidden('Only an owner can remove another owner');
      const owners = await prisma.organizationMember.count({ where: { orgId: params.orgId, role: 'owner' } });
      if (owners <= 1) throw new AppError(409, 'last_owner', 'An organization needs at least one owner');
    }
    await prisma.organizationMember.delete({ where: { orgId_userId: { orgId: params.orgId, userId: params.userId } } });
    await logEvent(prisma, { userId: user.id, actorUserId: user.id, eventType: 'org_member_removed', metadata: { orgId: params.orgId, member: params.userId } });
    return { ok: true };
  });
}

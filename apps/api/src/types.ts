import type { PrismaClient, User, Session } from '@prisma/client';
import type { AppConfig } from './config';
import type { GeoProvider } from './lib/geo';
import type { KeyringManager } from './lib/keyring';
import type { Mailer } from './lib/mail';
import type { ObjectStorage } from './lib/storage';

export interface AppDeps {
  config: AppConfig;
  prisma: PrismaClient;
  storage: ObjectStorage;
  geo: GeoProvider;
  mailer: Mailer;
  /** Injectable clock so expiry can be tested without waiting. */
  now: () => Date;
  /** Reloads keys after a rotation. Absent in scripts that never wrap or unwrap data keys. */
  keys?: KeyringManager;
}

export interface AuthContext {
  user: User;
  session: Session;
}

declare module 'fastify' {
  interface FastifyInstance {
    deps: AppDeps;
  }
  interface FastifyRequest {
    auth: AuthContext | null;
    /** The visitor's address: the trusted edge header when configured, otherwise the proxy-aware request.ip. */
    clientIp: string;
  }
}

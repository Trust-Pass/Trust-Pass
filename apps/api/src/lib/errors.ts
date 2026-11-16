import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError, type ZodTypeAny, type output } from 'zod';

/** An error whose message is safe to show to the client. */
export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export const notFound = (what = 'Resource') => new AppError(404, 'not_found', `${what} not found`);
export const forbidden = (message = 'You do not have permission to do this') =>
  new AppError(403, 'forbidden', message);
export const badRequest = (message: string, details?: Record<string, unknown>) =>
  new AppError(400, 'bad_request', message, details);
export const unauthorized = (message = 'Please sign in to continue') =>
  new AppError(401, 'unauthorized', message);

export function parse<S extends ZodTypeAny>(schema: S, data: unknown): output<S> {
  const result = schema.safeParse(data);
  if (!result.success) throw result.error;
  return result.data as output<S>;
}

/**
 * Clients get a generic message plus a request id. Stack traces and internal
 * details only go to the server log.
 */
export function errorHandler(error: FastifyError | Error, request: FastifyRequest, reply: FastifyReply) {
  if (error instanceof AppError) {
    return reply.status(error.statusCode).send({
      error: { code: error.code, message: error.message, ...(error.details ? { details: error.details } : {}) },
      requestId: request.id,
    });
  }
  if (error instanceof ZodError) {
    const fields: Record<string, string> = {};
    for (const issue of error.issues) {
      const key = issue.path.join('.') || '_';
      if (!fields[key]) fields[key] = issue.message;
    }
    return reply.status(400).send({
      error: { code: 'validation_error', message: 'Some fields need attention', details: { fields } },
      requestId: request.id,
    });
  }
  const fastifyError = error as FastifyError;
  const status = fastifyError.statusCode ?? 500;
  if (status === 429) {
    return reply.status(429).send({
      error: { code: 'rate_limited', message: 'Too many requests. Please wait a moment and try again.' },
      requestId: request.id,
    });
  }
  if (status === 413 || fastifyError.code === 'FST_REQ_FILE_TOO_LARGE') {
    return reply.status(413).send({
      error: { code: 'file_too_large', message: 'The file is larger than the allowed limit' },
      requestId: request.id,
    });
  }
  if (status >= 400 && status < 500) {
    request.log.info({ err: error }, 'client error');
    return reply.status(status).send({
      error: { code: 'bad_request', message: 'The request could not be processed' },
      requestId: request.id,
    });
  }
  request.log.error({ err: error }, 'unhandled error');
  return reply.status(500).send({
    error: { code: 'internal_error', message: 'Something went wrong on our side. Please try again.' },
    requestId: request.id,
  });
}

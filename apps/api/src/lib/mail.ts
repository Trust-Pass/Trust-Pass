import nodemailer from 'nodemailer';
import type { FastifyBaseLogger } from 'fastify';
import type { AppConfig } from '../config';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  readonly transport: 'console' | 'smtp' | 'none';
  send(message: MailMessage): Promise<void>;
}

/**
 * console: prints the email to the server log (development only, because it
 *   can contain a password-reset link).
 * smtp:    sends through SMTP_URL.
 * none:    drops the email (production without an email provider).
 */
export function createMailer(config: AppConfig, log: FastifyBaseLogger): Mailer {
  let transport = config.env.MAIL_TRANSPORT;
  if (transport === 'console' && config.isProduction) {
    log.warn('MAIL_TRANSPORT=console is disabled in production; emails will not be sent');
    transport = 'none';
  }

  if (transport === 'smtp') {
    if (!config.env.SMTP_URL) throw new Error('MAIL_TRANSPORT=smtp requires SMTP_URL');
    const smtp = nodemailer.createTransport(config.env.SMTP_URL);
    return {
      transport,
      async send(message) {
        await smtp.sendMail({ from: config.env.MAIL_FROM, ...message });
      },
    };
  }

  if (transport === 'console') {
    return {
      transport,
      async send(message) {
        log.info({ mail: message }, `[dev mail] to=${message.to} subject="${message.subject}"\n${message.text}`);
      },
    };
  }

  return {
    transport: 'none',
    async send(message) {
      log.warn({ to: '[redacted]', subject: message.subject }, 'email not sent: no mail transport configured');
    },
  };
}

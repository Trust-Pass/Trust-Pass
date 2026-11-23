import { z } from 'zod';
import { isCountryCode } from './countries';

export * from './countries';
export * from './qr-shield';

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export const ORGANIZATION_TYPES = ['company', 'university', 'government', 'other'] as const;
export type OrganizationType = (typeof ORGANIZATION_TYPES)[number];

export const ORG_ROLES = ['owner', 'admin', 'member'] as const;
export type OrgRole = (typeof ORG_ROLES)[number];

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, 'Email is too long')
  .email('Enter a valid email address');

export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Use at least ${PASSWORD_MIN_LENGTH} characters`)
  .max(PASSWORD_MAX_LENGTH, `Use at most ${PASSWORD_MAX_LENGTH} characters`);

export const fullNameSchema = z
  .string()
  .trim()
  .min(2, 'Enter your full name')
  .max(100, 'Name is too long');

const baseRegister = {
  fullName: fullNameSchema,
  email: emailSchema,
  password: passwordSchema,
};

export const registerSchema = z.discriminatedUnion('accountType', [
  z.object({ accountType: z.literal('individual'), ...baseRegister }),
  z.object({
    accountType: z.literal('organization'),
    ...baseRegister,
    organizationName: z.string().trim().min(2, 'Enter the organization name').max(100),
    organizationType: z.enum(ORGANIZATION_TYPES),
  }),
]);
export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Enter your password').max(PASSWORD_MAX_LENGTH),
});

export const passwordResetRequestSchema = z.object({ email: emailSchema });

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(20).max(200),
  password: passwordSchema,
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(PASSWORD_MAX_LENGTH),
  newPassword: passwordSchema,
});

export const updateProfileSchema = z.object({ fullName: fullNameSchema });

export const addMemberSchema = z.object({
  email: emailSchema,
  role: z.enum(['admin', 'member']),
});

export const updateMemberSchema = z.object({ role: z.enum(ORG_ROLES) });

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

export const DOCUMENT_CATEGORIES = [
  'university_certificate',
  'enrollment_certificate',
  'professional_certificate',
  'employment_document',
  'identity_document',
  'other',
] as const;
export type DocumentCategory = (typeof DOCUMENT_CATEGORIES)[number];

export const DOCUMENT_CATEGORY_LABELS: Record<DocumentCategory, string> = {
  university_certificate: 'University certificate',
  enrollment_certificate: 'Enrollment certificate',
  professional_certificate: 'Professional certificate',
  employment_document: 'Employment document',
  identity_document: 'Identity document',
  other: 'Other',
};

export const ALLOWED_UPLOAD_TYPES = ['application/pdf', 'image/png', 'image/jpeg'] as const;
export const MAX_CLAIMS_PER_DOCUMENT = 20;

export const selfDeclaredClaimSchema = z.object({
  label: z.string().trim().min(1, 'Enter a field name').max(60),
  value: z.string().trim().min(1, 'Enter a value').max(200),
});

export const documentMetadataSchema = z.object({
  title: z.string().trim().min(1, 'Enter a title').max(120),
  category: z.enum(DOCUMENT_CATEGORIES),
  claims: z.array(selfDeclaredClaimSchema).max(MAX_CLAIMS_PER_DOCUMENT).default([]),
});
export type DocumentMetadataInput = z.infer<typeof documentMetadataSchema>;

// ---------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------

export const EXPIRY_PRESETS = {
  '1h': 60 * 60,
  '24h': 24 * 60 * 60,
  '3d': 3 * 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
} as const;
export type ExpiryPreset = keyof typeof EXPIRY_PRESETS;

export const EXPIRY_LABELS: Record<ExpiryPreset | 'custom', string> = {
  '1h': '1 hour',
  '24h': '24 hours',
  '3d': '3 days',
  '7d': '7 days',
  custom: 'Custom date',
};

export const countryCodeSchema = z
  .string()
  .trim()
  .toUpperCase()
  .refine(isCountryCode, 'Unknown country code');

export const allowedCountriesSchema = z
  .array(countryCodeSchema)
  .max(60, 'Choose at most 60 countries')
  .transform((codes) => Array.from(new Set(codes)));

export const RECIPIENT_TYPES = ['anyone', 'organization'] as const;
export type RecipientType = (typeof RECIPIENT_TYPES)[number];

export const FILE_MODES = ['original', 'redacted'] as const;
export type FileMode = (typeof FILE_MODES)[number];
export const MAX_REDACTIONS = 200;
/** Page images of a redacted copy: at most this many pixels on the long side (about 200 dpi on A4). */
export const REDACTION_MAX_EDGE = 2400;
/** Most bytes of rendered page images one redacted-copy request may carry (all pages together). */
export const REDACTION_MAX_TOTAL_BYTES = 40 * 1024 * 1024;

const unit = z.number().min(0).max(1);
/**
 * How a hidden area looks in the shared copy. Every style replaces the pixels: pixelate and blur
 * are drawn fresh from random values, never from what was underneath, so nothing can be recovered.
 */
export const REDACTION_STYLES = ['black', 'white', 'pixelate', 'blur'] as const;
export type RedactionStyle = (typeof REDACTION_STYLES)[number];
export const REDACTION_STYLE_LABELS: Record<RedactionStyle, string> = {
  black: 'Black box',
  white: 'White-out',
  pixelate: 'Pixelate',
  blur: 'Blur',
};

/** What a hidden area holds, so the owner can show or hide a whole category at once. */
export const SENSITIVE_KINDS = ['id', 'passport', 'phone', 'email', 'address', 'financial', 'photo', 'signature', 'custom', 'manual'] as const;
export type SensitiveKind = (typeof SENSITIVE_KINDS)[number];
export const SENSITIVE_KIND_LABELS: Record<SensitiveKind, string> = {
  id: 'ID numbers',
  passport: 'Passport numbers',
  phone: 'Phone numbers',
  email: 'Email addresses',
  address: 'Addresses',
  financial: 'Financial details',
  photo: 'Photos and pictures',
  signature: 'Signatures',
  custom: 'Text you searched for',
  manual: 'Areas you marked',
};

export const redactionSchema = z
  .object({
    page: z.number().int().min(0).max(49),
    x: unit,
    y: unit,
    w: unit,
    h: unit,
    style: z.enum(REDACTION_STYLES).default('black'),
    kind: z.enum(SENSITIVE_KINDS).default('manual'),
  })
  .refine((r) => r.w > 0 && r.h > 0 && r.x + r.w <= 1.000001 && r.y + r.h <= 1.000001, { message: 'An area lies outside the page' });
export type Redaction = z.output<typeof redactionSchema>;
export type RedactionInput = z.input<typeof redactionSchema>;

/** The owner's saved choice of what to hide in shared copies of a document (set at upload or later). */
export const redactionPlanSchema = z.object({ redactions: z.array(redactionSchema).max(MAX_REDACTIONS) });

/**
 * Watermark of a link's recipient copies (view and download). Optional and OFF unless the owner
 * turns it on; when on, the owner chooses its text, look and position.
 */
export const WATERMARK_STYLES = ['full', 'diagonal', 'bands'] as const;
export type WatermarkStyle = (typeof WATERMARK_STYLES)[number];
export const WATERMARK_COLORS = ['navy', 'teal', 'crimson', 'gray'] as const;
export type WatermarkColor = (typeof WATERMARK_COLORS)[number];
export const WATERMARK_STRENGTHS = ['light', 'medium', 'strong'] as const;
export type WatermarkStrength = (typeof WATERMARK_STRENGTHS)[number];
export const WATERMARK_POSITIONS = ['tiled', 'center', 'top', 'bottom'] as const;
export type WatermarkPosition = (typeof WATERMARK_POSITIONS)[number];
export const WATERMARK_POSITION_LABELS: Record<WatermarkPosition, string> = {
  tiled: 'Across the page',
  center: 'Centre',
  top: 'Top',
  bottom: 'Bottom',
};
export const WATERMARK_DEFAULT_TEXT = 'CONFIDENTIAL';
export const WATERMARK_STYLE_LABELS: Record<WatermarkStyle, string> = {
  full: 'Stamp and name bands',
  diagonal: 'Diagonal stamp only',
  bands: 'Name bands only',
};

export const watermarkSchema = z.object({
  enabled: z.boolean().default(false),
  style: z.enum(WATERMARK_STYLES).default('full'),
  /** The diagonal stamp word. The standard PDF fonts only draw Latin characters. */
  text: z
    .string()
    .trim()
    .max(24, 'Keep the stamp to 24 characters')
    .regex(/^[A-Za-z0-9 .,:;'!?&()/#+-]*$/, 'Use Latin letters, digits and basic punctuation for the stamp')
    .default(WATERMARK_DEFAULT_TEXT)
    .transform((t) => (t.length === 0 ? WATERMARK_DEFAULT_TEXT : t)),
  color: z.enum(WATERMARK_COLORS).default('navy'),
  strength: z.enum(WATERMARK_STRENGTHS).default('light'),
  position: z.enum(WATERMARK_POSITIONS).default('tiled'),
});
export type WatermarkSettings = z.output<typeof watermarkSchema>;
/** A new link: no watermark until the owner turns it on. */
export const DEFAULT_WATERMARK: WatermarkSettings = { enabled: false, style: 'full', text: WATERMARK_DEFAULT_TEXT, color: 'navy', strength: 'light', position: 'tiled' };
/** The watermark every link made before watermark control was created with; they keep it. */
export const STANDARD_WATERMARK: WatermarkSettings = { ...DEFAULT_WATERMARK, enabled: true };

export const createLinkSchema = z
  .object({
    claimIds: z.array(z.string().uuid()).max(MAX_CLAIMS_PER_DOCUMENT).default([]),
    includeFile: z.boolean(),
    /** Recipient may download a separate watermarked PDF. Only with includeFile. */
    allowDownload: z.boolean().default(false),
    /** With includeFile: the original file, or a redacted copy with the owner's boxes burned in. */
    fileMode: z.enum(FILE_MODES).default('original'),
    /** Areas to hide in the redacted copy, as fractions of each page (0 = left/top, 1 = right/bottom). */
    redactions: z.array(redactionSchema).max(MAX_REDACTIONS).default([]),
    recipientType: z.enum(RECIPIENT_TYPES),
    recipientOrgId: z.string().uuid().optional(),
    recipientLabel: z.string().trim().min(1, 'Name the recipient').max(80),
    expiresIn: z.enum(['1h', '24h', '3d', '7d', 'custom']),
    expiresAt: z.string().datetime({ offset: true }).optional(),
    allowedCountries: allowedCountriesSchema.default([]),
    watermark: watermarkSchema.prefault({}),
  })
  .superRefine((value, ctx) => {
    if (value.fileMode === 'redacted' && !value.includeFile) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['fileMode'], message: 'A redacted copy needs the file to be shared' });
    }
    if (value.fileMode === 'redacted' && value.redactions.length === 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['redactions'], message: 'Mark at least one area to hide' });
    }
    if (value.fileMode === 'original' && value.redactions.length > 0) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['redactions'], message: 'Hidden areas only apply to a redacted copy' });
    }
    if (value.allowDownload && !value.includeFile) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['allowDownload'],
        message: 'Downloads need the file to be shared',
      });
    }
    if (!value.includeFile && value.claimIds.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['claimIds'],
        message: 'Share at least one field or the file',
      });
    }
    if (value.recipientType === 'organization' && !value.recipientOrgId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['recipientOrgId'],
        message: 'Choose the recipient organization',
      });
    }
    if (value.expiresIn === 'custom' && !value.expiresAt) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expiresAt'],
        message: 'Pick an expiry date',
      });
    }
  });
export type CreateLinkInput = z.infer<typeof createLinkSchema>;

export const updateCountriesSchema = z.object({ allowedCountries: allowedCountriesSchema });

export const updateDownloadSchema = z.object({ allowDownload: z.boolean() });

export const updateWatermarkSchema = z.object({ watermark: watermarkSchema });

/**
 * Preview of the exact copy a recipient would get, built by the server and never stored.
 * Same file rules as createLinkSchema; the recipient name is optional here.
 */
export const previewLinkSchema = z
  .object({
    fileMode: z.enum(FILE_MODES).default('original'),
    redactions: z.array(redactionSchema).max(MAX_REDACTIONS).default([]),
    recipientLabel: z.string().trim().max(80).default(''),
    copy: z.enum(['view', 'download']).default('view'),
    watermark: watermarkSchema.prefault({}),
  })
  .superRefine((value, ctx) => {
    if (value.fileMode === 'redacted' && value.redactions.length === 0) {
      ctx.addIssue({ code: 'custom', path: ['redactions'], message: 'Mark at least one area to hide' });
    }
    if (value.fileMode === 'original' && value.redactions.length > 0) {
      ctx.addIssue({ code: 'custom', path: ['redactions'], message: 'Hidden areas only apply to a redacted copy' });
    }
  });
export type PreviewLinkInput = z.infer<typeof previewLinkSchema>;

// ---------------------------------------------------------------------------
// Access, verification and events
// ---------------------------------------------------------------------------

export const ACCESS_OUTCOMES = [
  'granted',
  'denied_revoked',
  'denied_expired',
  'denied_recipient',
  'denied_country',
] as const;
export type AccessOutcome = (typeof ACCESS_OUTCOMES)[number];

export const ACCESS_OUTCOME_LABELS: Record<AccessOutcome, string> = {
  granted: 'Granted',
  denied_revoked: 'Denied: link revoked',
  denied_expired: 'Denied: link expired',
  denied_recipient: 'Denied: not the recipient',
  denied_country: 'Denied: country not allowed',
};

export const VERIFICATION_RESULTS = ['verified', 'invalid', 'unverified'] as const;
export type VerificationResultValue = (typeof VERIFICATION_RESULTS)[number];

export const verifyPresentationSchema = z.object({
  presentation: z.string().trim().min(20).max(20000),
});

export const QR_SOURCES = ['camera', 'image', 'paste'] as const;
export type QrSource = (typeof QR_SOURCES)[number];

export const qrCheckSchema = z.object({
  content: z.string().min(1, 'Nothing to check').max(4096, 'That is too long to be a QR code (4096 characters at most)'),
  source: z.enum(QR_SOURCES),
});

export const DEMO_PROGRAMS = [
  'BSc Cybersecurity',
  'BSc Computer Science',
  'BSc Information Systems',
  'BSc Software Engineering',
  'MSc Data Science',
] as const;

/** Latin letters only: the certificate PDF uses standard fonts. */
export const certificateNameSchema = z
  .string()
  .trim()
  .min(2, 'Enter the name for the certificate')
  .max(80)
  .regex(/^[A-Za-z][A-Za-z .'-]*$/, 'Use English letters only (as on your passport)');

export const requestCredentialSchema = z.object({
  nameOnCertificate: certificateNameSchema,
  program: z.enum(DEMO_PROGRAMS),
});

/**
 * Sign-in history the owner may hide from their Activity Log view: successful sign-ins and
 * sign-outs. Failed sign-in attempts and account lockouts are security warnings and stay visible.
 * Hiding only filters the view; the append-only audit log is never changed.
 */
export const SIGN_IN_EVENT_TYPES = ['login_succeeded', 'logout', 'session_revoked'] as const;

export const SECURITY_EVENT_LABELS: Record<string, string> = {
  account_created: 'Account created',
  login_succeeded: 'Signed in',
  login_failed: 'Failed sign-in attempt',
  account_locked: 'Account temporarily locked',
  logout: 'Signed out',
  password_reset_requested: 'Password reset requested',
  password_reset_completed: 'Password reset completed',
  password_changed: 'Password changed',
  session_revoked: 'Session signed out remotely',
  profile_updated: 'Profile updated',
  document_uploaded: 'Document uploaded',
  document_encrypted: 'Document encrypted',
  document_deleted: 'Document deleted',
  credential_issued: 'Credential issued',
  link_created: 'Sharing link created',
  link_revoked: 'Sharing link revoked',
  link_countries_updated: 'Country rules updated',
  link_download_updated: 'Download permission changed',
  link_watermark_updated: 'Watermark changed',
  redaction_plan_saved: 'Hidden information chosen',
  document_encryption_checked: 'Encryption checked',
  recipient_downloaded: 'Recipient downloaded a copy',
  verification_completed: 'Verification completed',
  org_member_added: 'Organization member added',
  org_member_removed: 'Organization member removed',
  org_member_role_changed: 'Organization member role changed',
  admin_user_status_changed: 'User status changed by admin',
  admin_org_status_changed: 'Organization status changed by admin',
  admin_issuer_status_changed: 'Issuer trust changed by admin',
  admin_settings_updated: 'System settings updated',
  log_retention_run: 'Log retention cleanup',
  repeated_denied_access: 'Several blocked attempts on one link',
  integrity_check_failed: 'Stored file failed its integrity check',
  invalid_link_attempt: 'Attempt with an invalid link',
  qr_threat_detected: 'Dangerous QR code or link detected',
};

export const updateSettingsSchema = z.object({
  maxLinkDays: z.number().int().min(1).max(365),
  logRetentionDays: z.number().int().min(7).max(730),
  credentialsPerUser: z.number().int().min(1).max(20),
});
export type SystemSettings = z.infer<typeof updateSettingsSchema>;

export const DEFAULT_SETTINGS: SystemSettings = {
  maxLinkDays: 30,
  logRetentionDays: 90,
  credentialsPerUser: 3,
};

export const updateStatusSchema = z.object({ status: z.enum(['active', 'suspended']) });
export const updateIssuerStatusSchema = z.object({ status: z.enum(['trusted', 'revoked']) });

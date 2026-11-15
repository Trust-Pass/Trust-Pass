import { z } from 'zod';
import { isCountryCode } from './countries';

export * from './countries';

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

export const createLinkSchema = z
  .object({
    claimIds: z.array(z.string().uuid()).max(MAX_CLAIMS_PER_DOCUMENT).default([]),
    includeFile: z.boolean(),
    recipientType: z.enum(RECIPIENT_TYPES),
    recipientOrgId: z.string().uuid().optional(),
    recipientLabel: z.string().trim().min(1, 'Name the recipient').max(80),
    expiresIn: z.enum(['1h', '24h', '3d', '7d', 'custom']),
    expiresAt: z.string().datetime({ offset: true }).optional(),
    allowedCountries: allowedCountriesSchema.default([]),
  })
  .superRefine((value, ctx) => {
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
  verification_completed: 'Verification completed',
  org_member_added: 'Organization member added',
  org_member_removed: 'Organization member removed',
  org_member_role_changed: 'Organization member role changed',
  admin_user_status_changed: 'User status changed by admin',
  admin_org_status_changed: 'Organization status changed by admin',
  admin_issuer_status_changed: 'Issuer trust changed by admin',
  admin_settings_updated: 'System settings updated',
  log_retention_run: 'Log retention cleanup',
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

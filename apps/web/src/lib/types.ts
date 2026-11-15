export type TrustStatus = 'verified' | 'invalid' | 'unverified';

export interface User {
  id: string;
  email: string;
  fullName: string;
  accountType: 'individual' | 'organization';
  role: 'user' | 'admin';
  createdAt: string;
}

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  type: string;
  role: 'owner' | 'admin' | 'member';
}

export interface Me {
  user: User;
  organizations: OrgSummary[];
  csrfToken: string;
  unreadNotifications: number;
}

export interface DocumentSummary {
  id: string;
  title: string;
  category: string;
  kind: 'file' | 'credential';
  mimeType: string;
  sizeBytes: number;
  createdAt: string;
  claimCount: number;
  activeLinks: number;
  totalLinks: number;
  trust: { status: TrustStatus; label: string };
}

export interface VerificationCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface Verification {
  result: TrustStatus;
  reason: string;
  checks: VerificationCheck[];
  issuer: { id: string; name: string; simulated: boolean; status: string } | null;
  claims: Array<{ key: string; label: string; value: string }>;
  credentialId: string | null;
  expiresAt: string | null;
}

export interface Claim {
  id: string;
  key: string;
  label: string;
  value: string;
  source: 'issuer' | 'self_declared';
}

export type LinkStatus = 'active' | 'expired' | 'revoked';

export interface DocumentLink {
  id: string;
  recipientLabel: string;
  recipientType: 'anyone' | 'organization';
  recipientOrg: string | null;
  includeFile: boolean;
  claimCount: number;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
  viewCount: number;
  countries: string[];
  status: LinkStatus;
}

export interface DocumentDetail {
  id: string;
  title: string;
  category: string;
  kind: 'file' | 'credential';
  mimeType: string;
  sizeBytes: number;
  createdAt: string;
  sha256: string;
  encryption: { algorithm: string; keyWrapping: string; perDocumentKey: boolean };
  trust: { status: TrustStatus; label: string };
  credential: { id: string; issuer: string; simulatedIssuer: boolean; issuedAt: string; expiresAt: string; format: string } | null;
  verification: Verification | null;
  claims: Claim[];
  links: DocumentLink[];
}

export interface SharedView {
  link: {
    id: string;
    recipientLabel: string;
    recipientType: 'anyone' | 'organization';
    recipientOrg: string | null;
    sharedBy: string;
    sharedAt: string;
    expiresAt: string;
    viewOnly: boolean;
  };
  document: { title: string; category: string; kind: 'file' | 'credential'; fileShared: boolean; mimeType: string | null };
  fields: Array<{ label: string; value: string; source: 'issuer' | 'self_declared' }>;
  verification: Verification;
  presentation: string | null;
  viewer: { approximateCountry: string | null };
  notice: string;
}

export interface LinkSummary {
  id: string;
  document: { id: string; title: string; kind: string };
  recipientLabel: string;
  recipientType: 'anyone' | 'organization';
  recipientOrg: string | null;
  includeFile: boolean;
  claimCount: number;
  countries: string[];
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
  lastAccessedAt: string | null;
  status: LinkStatus;
  attempts: { granted: number; denied: number; total: number };
}

export type AccessOutcome = 'granted' | 'denied_revoked' | 'denied_expired' | 'denied_recipient' | 'denied_country';

export interface Notification {
  id: string;
  type: string;
  title: string;
  body: string;
  read: boolean;
  at: string;
  linkId: string | null;
  documentId: string | null;
}

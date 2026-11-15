-- CreateEnum
CREATE TYPE "AccountType" AS ENUM ('individual', 'organization');

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('user', 'admin');

-- CreateEnum
CREATE TYPE "AccountStatus" AS ENUM ('active', 'suspended');

-- CreateEnum
CREATE TYPE "OrganizationType" AS ENUM ('company', 'university', 'government', 'other');

-- CreateEnum
CREATE TYPE "OrgRole" AS ENUM ('owner', 'admin', 'member');

-- CreateEnum
CREATE TYPE "DocumentCategory" AS ENUM ('university_certificate', 'enrollment_certificate', 'professional_certificate', 'employment_document', 'identity_document', 'other');

-- CreateEnum
CREATE TYPE "DocumentKind" AS ENUM ('file', 'credential');

-- CreateEnum
CREATE TYPE "ClaimSource" AS ENUM ('issuer', 'self_declared');

-- CreateEnum
CREATE TYPE "IssuerStatus" AS ENUM ('trusted', 'revoked');

-- CreateEnum
CREATE TYPE "RecipientType" AS ENUM ('anyone', 'organization');

-- CreateEnum
CREATE TYPE "VerificationResult" AS ENUM ('verified', 'invalid', 'unverified');

-- CreateEnum
CREATE TYPE "VerificationMethod" AS ENUM ('file', 'presentation', 'share_link');

-- CreateEnum
CREATE TYPE "AccessOutcome" AS ENUM ('granted', 'denied_revoked', 'denied_expired', 'denied_recipient', 'denied_country');

-- CreateEnum
CREATE TYPE "AccessResource" AS ENUM ('details', 'file');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('info', 'warning', 'high');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "full_name" TEXT NOT NULL,
    "account_type" "AccountType" NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'user',
    "status" "AccountStatus" NOT NULL DEFAULT 'active',
    "failed_logins" INTEGER NOT NULL DEFAULT 0,
    "locked_until" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "csrf_token" TEXT NOT NULL,
    "user_agent_family" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_tokens" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_reset_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organizations" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "type" "OrganizationType" NOT NULL,
    "status" "AccountStatus" NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "organization_members" (
    "org_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role" "OrgRole" NOT NULL DEFAULT 'member',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organization_members_pkey" PRIMARY KEY ("org_id","user_id")
);

-- CreateTable
CREATE TABLE "documents" (
    "id" UUID NOT NULL,
    "owner_id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "category" "DocumentCategory" NOT NULL,
    "kind" "DocumentKind" NOT NULL,
    "mime_type" TEXT NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "storage_key" TEXT NOT NULL,
    "plaintext_sha256" TEXT NOT NULL,
    "enc_iv" BYTEA NOT NULL,
    "enc_tag" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "deleted_at" TIMESTAMPTZ(3),

    CONSTRAINT "documents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "document_keys" (
    "document_id" UUID NOT NULL,
    "wrapped_dek" BYTEA NOT NULL,
    "wrap_iv" BYTEA NOT NULL,
    "wrap_tag" BYTEA NOT NULL,
    "kek_version" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "document_keys_pkey" PRIMARY KEY ("document_id")
);

-- CreateTable
CREATE TABLE "document_claims" (
    "id" UUID NOT NULL,
    "document_id" UUID NOT NULL,
    "claim_key" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "value_encrypted" BYTEA NOT NULL,
    "disclosure_encrypted" BYTEA,
    "source" "ClaimSource" NOT NULL,
    "position" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "document_claims_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "issuers" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "kid" TEXT NOT NULL,
    "public_key_jwk" JSONB NOT NULL,
    "status" "IssuerStatus" NOT NULL DEFAULT 'trusted',
    "is_simulated" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "issuers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "credentials" (
    "id" UUID NOT NULL,
    "document_id" UUID NOT NULL,
    "issuer_id" UUID NOT NULL,
    "format" TEXT NOT NULL DEFAULT 'sd-jwt',
    "credential_encrypted" BYTEA NOT NULL,
    "document_hash" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sharing_links" (
    "id" UUID NOT NULL,
    "document_id" UUID NOT NULL,
    "owner_id" UUID NOT NULL,
    "token_hash" TEXT NOT NULL,
    "token_encrypted" BYTEA NOT NULL,
    "recipient_type" "RecipientType" NOT NULL,
    "recipient_org_id" UUID,
    "recipient_label" TEXT NOT NULL,
    "include_file" BOOLEAN NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "last_accessed_at" TIMESTAMPTZ(3),
    "view_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sharing_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sharing_permissions" (
    "link_id" UUID NOT NULL,
    "claim_id" UUID NOT NULL,

    CONSTRAINT "sharing_permissions_pkey" PRIMARY KEY ("link_id","claim_id")
);

-- CreateTable
CREATE TABLE "allowed_countries" (
    "link_id" UUID NOT NULL,
    "country_code" CHAR(2) NOT NULL,

    CONSTRAINT "allowed_countries_pkey" PRIMARY KEY ("link_id","country_code")
);

-- CreateTable
CREATE TABLE "verification_records" (
    "id" UUID NOT NULL,
    "result" "VerificationResult" NOT NULL,
    "method" "VerificationMethod" NOT NULL,
    "reason" TEXT NOT NULL,
    "checks" JSONB NOT NULL,
    "document_id" UUID,
    "credential_id" UUID,
    "link_id" UUID,
    "issuer_id" UUID,
    "verified_by_user_id" UUID,
    "verified_by_org_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "verification_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "access_logs" (
    "id" BIGSERIAL NOT NULL,
    "link_id" UUID NOT NULL,
    "document_id" UUID NOT NULL,
    "owner_id" UUID NOT NULL,
    "resource" "AccessResource" NOT NULL,
    "outcome" "AccessOutcome" NOT NULL,
    "country_code" CHAR(2),
    "ip_hmac" TEXT,
    "user_agent_family" TEXT,
    "accessor_user_id" UUID,
    "accessor_org_id" UUID,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "access_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" BIGSERIAL NOT NULL,
    "user_id" UUID,
    "actor_user_id" UUID,
    "event_type" TEXT NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'info',
    "document_id" UUID,
    "link_id" UUID,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notifications" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "link_id" UUID,
    "document_id" UUID,
    "read_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system_settings" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updated_by" UUID,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "system_settings_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "stored_objects" (
    "key" TEXT NOT NULL,
    "data" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "stored_objects_pkey" PRIMARY KEY ("key")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_token_hash_key" ON "sessions"("token_hash");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_tokens_token_hash_key" ON "password_reset_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "password_reset_tokens_user_id_idx" ON "password_reset_tokens"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations"("slug");

-- CreateIndex
CREATE INDEX "organizations_name_idx" ON "organizations"("name");

-- CreateIndex
CREATE INDEX "organization_members_user_id_idx" ON "organization_members"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "documents_storage_key_key" ON "documents"("storage_key");

-- CreateIndex
CREATE INDEX "documents_owner_id_created_at_idx" ON "documents"("owner_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "document_claims_document_id_claim_key_key" ON "document_claims"("document_id", "claim_key");

-- CreateIndex
CREATE UNIQUE INDEX "issuers_identifier_key" ON "issuers"("identifier");

-- CreateIndex
CREATE UNIQUE INDEX "issuers_kid_key" ON "issuers"("kid");

-- CreateIndex
CREATE UNIQUE INDEX "credentials_document_id_key" ON "credentials"("document_id");

-- CreateIndex
CREATE INDEX "credentials_document_hash_idx" ON "credentials"("document_hash");

-- CreateIndex
CREATE INDEX "credentials_issuer_id_idx" ON "credentials"("issuer_id");

-- CreateIndex
CREATE UNIQUE INDEX "sharing_links_token_hash_key" ON "sharing_links"("token_hash");

-- CreateIndex
CREATE INDEX "sharing_links_owner_id_created_at_idx" ON "sharing_links"("owner_id", "created_at");

-- CreateIndex
CREATE INDEX "sharing_links_document_id_idx" ON "sharing_links"("document_id");

-- CreateIndex
CREATE INDEX "sharing_links_recipient_org_id_idx" ON "sharing_links"("recipient_org_id");

-- CreateIndex
CREATE INDEX "sharing_permissions_claim_id_idx" ON "sharing_permissions"("claim_id");

-- CreateIndex
CREATE INDEX "verification_records_verified_by_user_id_created_at_idx" ON "verification_records"("verified_by_user_id", "created_at");

-- CreateIndex
CREATE INDEX "verification_records_verified_by_org_id_created_at_idx" ON "verification_records"("verified_by_org_id", "created_at");

-- CreateIndex
CREATE INDEX "verification_records_document_id_idx" ON "verification_records"("document_id");

-- CreateIndex
CREATE INDEX "access_logs_owner_id_created_at_idx" ON "access_logs"("owner_id", "created_at");

-- CreateIndex
CREATE INDEX "access_logs_link_id_created_at_idx" ON "access_logs"("link_id", "created_at");

-- CreateIndex
CREATE INDEX "access_logs_document_id_created_at_idx" ON "access_logs"("document_id", "created_at");

-- CreateIndex
CREATE INDEX "security_events_user_id_created_at_idx" ON "security_events"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "security_events_event_type_created_at_idx" ON "security_events"("event_type", "created_at");

-- CreateIndex
CREATE INDEX "security_events_created_at_idx" ON "security_events"("created_at");

-- CreateIndex
CREATE INDEX "notifications_user_id_created_at_idx" ON "notifications"("user_id", "created_at");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "organization_members" ADD CONSTRAINT "organization_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "documents" ADD CONSTRAINT "documents_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "document_keys" ADD CONSTRAINT "document_keys_document_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "document_claims" ADD CONSTRAINT "document_claims_document_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_document_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_issuer_id_fkey" FOREIGN KEY ("issuer_id") REFERENCES "issuers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sharing_links" ADD CONSTRAINT "sharing_links_document_id_fkey" FOREIGN KEY ("document_id") REFERENCES "documents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sharing_links" ADD CONSTRAINT "sharing_links_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sharing_links" ADD CONSTRAINT "sharing_links_recipient_org_id_fkey" FOREIGN KEY ("recipient_org_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sharing_permissions" ADD CONSTRAINT "sharing_permissions_link_id_fkey" FOREIGN KEY ("link_id") REFERENCES "sharing_links"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sharing_permissions" ADD CONSTRAINT "sharing_permissions_claim_id_fkey" FOREIGN KEY ("claim_id") REFERENCES "document_claims"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "allowed_countries" ADD CONSTRAINT "allowed_countries_link_id_fkey" FOREIGN KEY ("link_id") REFERENCES "sharing_links"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Hand-written constraints (not expressible in the Prisma schema)
-- ---------------------------------------------------------------------------

-- Emails are stored lower-case so uniqueness is case-insensitive.
ALTER TABLE "users" ADD CONSTRAINT "users_email_lowercase" CHECK ("email" = lower("email"));

-- A link must expire after it was created.
ALTER TABLE "sharing_links" ADD CONSTRAINT "sharing_links_expiry_after_creation" CHECK ("expires_at" > "created_at");

-- Organization links must name the organization.
ALTER TABLE "sharing_links" ADD CONSTRAINT "sharing_links_org_recipient" CHECK (
  ("recipient_type" = 'organization' AND "recipient_org_id" IS NOT NULL) OR
  ("recipient_type" = 'anyone' AND "recipient_org_id" IS NULL)
);

-- Country codes are two upper-case letters.
ALTER TABLE "allowed_countries" ADD CONSTRAINT "allowed_countries_code_format" CHECK ("country_code" ~ '^[A-Z]{2}$');
ALTER TABLE "access_logs" ADD CONSTRAINT "access_logs_country_format" CHECK ("country_code" IS NULL OR "country_code" ~ '^[A-Z]{2}$');

-- A link may only disclose claims of its own document.
CREATE FUNCTION trustpass_check_permission_document() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM "sharing_links" l
    JOIN "document_claims" c ON c."document_id" = l."document_id"
    WHERE l."id" = NEW."link_id" AND c."id" = NEW."claim_id"
  ) THEN
    RAISE EXCEPTION 'claim % does not belong to the document of link %', NEW."claim_id", NEW."link_id";
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "sharing_permissions_same_document"
  BEFORE INSERT OR UPDATE ON "sharing_permissions"
  FOR EACH ROW EXECUTE FUNCTION trustpass_check_permission_document();

-- ---------------------------------------------------------------------------
-- Append-only audit tables
-- UPDATE, DELETE and TRUNCATE are rejected unless the current transaction
-- explicitly enables the retention purge (SET LOCAL trustpass.allow_log_purge = 'on').
-- ---------------------------------------------------------------------------

CREATE FUNCTION trustpass_protect_audit_log() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    IF coalesce(current_setting('trustpass.allow_log_purge', true), 'off') = 'on' THEN
      IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
      RETURN NULL;
    END IF;
  END IF;
  RAISE EXCEPTION 'audit table % is append-only (% rejected)', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "access_logs_append_only"
  BEFORE UPDATE OR DELETE ON "access_logs"
  FOR EACH ROW EXECUTE FUNCTION trustpass_protect_audit_log();
CREATE TRIGGER "access_logs_no_truncate"
  BEFORE TRUNCATE ON "access_logs"
  FOR EACH STATEMENT EXECUTE FUNCTION trustpass_protect_audit_log();

CREATE TRIGGER "security_events_append_only"
  BEFORE UPDATE OR DELETE ON "security_events"
  FOR EACH ROW EXECUTE FUNCTION trustpass_protect_audit_log();
CREATE TRIGGER "security_events_no_truncate"
  BEFORE TRUNCATE ON "security_events"
  FOR EACH STATEMENT EXECUTE FUNCTION trustpass_protect_audit_log();

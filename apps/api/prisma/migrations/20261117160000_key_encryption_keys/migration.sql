-- E2: key-encryption keys protected by a key management service.
-- Additive only: no existing table or row is changed.

CREATE TABLE "key_encryption_keys" (
    "purpose" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "provider" TEXT NOT NULL,
    "kms_key_name" TEXT NOT NULL,
    "encrypted_key" BYTEA NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retired_at" TIMESTAMPTZ(3),

    CONSTRAINT "key_encryption_keys_pkey" PRIMARY KEY ("purpose", "version"),
    CONSTRAINT "key_encryption_keys_purpose_check" CHECK ("purpose" IN ('kek', 'link_token')),
    CONSTRAINT "key_encryption_keys_provider_check" CHECK ("provider" IN ('gcp-kms', 'fake-kms')),
    CONSTRAINT "key_encryption_keys_status_check" CHECK ("status" IN ('active', 'retired')),
    CONSTRAINT "key_encryption_keys_version_check" CHECK ("version" >= 1),
    -- A 32-byte key plus the KMS's own IV and tag is always longer than 32 bytes:
    -- this rejects a plaintext key stored by mistake.
    CONSTRAINT "key_encryption_keys_encrypted_check" CHECK (length("encrypted_key") > 32)
);

-- At most one active key per purpose.
CREATE UNIQUE INDEX "key_encryption_keys_one_active" ON "key_encryption_keys" ("purpose") WHERE "status" = 'active';

-- Keys cannot be deleted, truncated or altered (only status / retired_at may change), unless the
-- current transaction explicitly allows destroying keys:
--   SELECT set_config('trustpass.allow_key_destroy', 'on', true)
CREATE FUNCTION trustpass_protect_keyring() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    IF current_setting('trustpass.allow_key_destroy', true) = 'on' THEN
      RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NULL END;
    END IF;
    RAISE EXCEPTION 'key_encryption_keys: keys cannot be deleted (it would make documents unreadable)';
  END IF;
  IF NEW."purpose" <> OLD."purpose" OR NEW."version" <> OLD."version" OR NEW."provider" <> OLD."provider"
     OR NEW."kms_key_name" <> OLD."kms_key_name" OR NEW."encrypted_key" <> OLD."encrypted_key"
     OR NEW."created_at" <> OLD."created_at" THEN
    RAISE EXCEPTION 'key_encryption_keys: only status and retired_at can change';
  END IF;
  IF OLD."status" = 'retired' AND NEW."status" = 'active' THEN
    RAISE EXCEPTION 'key_encryption_keys: a retired key cannot become active again';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "key_encryption_keys_protect"
  BEFORE UPDATE OR DELETE ON "key_encryption_keys"
  FOR EACH ROW EXECUTE FUNCTION trustpass_protect_keyring();
CREATE TRIGGER "key_encryption_keys_no_truncate"
  BEFORE TRUNCATE ON "key_encryption_keys"
  FOR EACH STATEMENT EXECUTE FUNCTION trustpass_protect_keyring();

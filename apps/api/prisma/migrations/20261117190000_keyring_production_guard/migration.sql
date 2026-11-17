-- E2 review fix F: the fake KMS (development and tests only) must never write keys into
-- production's database. Production marks its database at start-up with
--   system_settings(key = 'environment', value = "production")
-- and from then on the database itself rejects any fake-kms key, whatever process tries.
-- Additive only: no existing row is changed.
--
-- NOTE for future migrations: trustpass_protect_keyring() (previous migration) names the
-- columns of key_encryption_keys. Renaming or dropping one of them requires updating that
-- function in the same migration, or every status change (retiring a key) will fail.

CREATE FUNCTION trustpass_refuse_fake_kms_in_production() RETURNS trigger AS $$
BEGIN
  IF NEW."provider" = 'fake-kms' AND EXISTS (
    SELECT 1 FROM "system_settings" WHERE "key" = 'environment' AND "value" = '"production"'::jsonb
  ) THEN
    RAISE EXCEPTION 'key_encryption_keys: fake-kms keys are refused in a production database';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "key_encryption_keys_no_fake_kms_in_production"
  BEFORE INSERT ON "key_encryption_keys"
  FOR EACH ROW EXECUTE FUNCTION trustpass_refuse_fake_kms_in_production();

-- The production marker itself cannot be removed or changed by the application.
CREATE FUNCTION trustpass_protect_environment_marker() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    IF EXISTS (SELECT 1 FROM "system_settings" WHERE "key" = 'environment' AND "value" = '"production"'::jsonb)
       AND current_setting('trustpass.allow_log_purge', true) IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'system_settings: the production marker cannot be removed';
    END IF;
    RETURN NULL;
  END IF;
  IF OLD."key" = 'environment' AND OLD."value" = '"production"'::jsonb THEN
    IF TG_OP = 'DELETE' OR NEW."value" IS DISTINCT FROM OLD."value" OR NEW."key" IS DISTINCT FROM OLD."key" THEN
      RAISE EXCEPTION 'system_settings: the production marker cannot be removed or changed';
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER "system_settings_protect_environment"
  BEFORE UPDATE OR DELETE ON "system_settings"
  FOR EACH ROW EXECUTE FUNCTION trustpass_protect_environment_marker();
CREATE TRIGGER "system_settings_protect_environment_truncate"
  BEFORE TRUNCATE ON "system_settings"
  FOR EACH STATEMENT EXECUTE FUNCTION trustpass_protect_environment_marker();

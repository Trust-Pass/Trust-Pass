import { defineKmsScenarios } from './gcp-kms-scenarios';

/**
 * LIVE tests against the real Google Cloud KMS. They run only when CI has these secrets
 * (GitHub > Settings > Secrets and variables > Actions):
 *   GCP_TEST_KMS_KEY_NAME          projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<test key>
 *   GCP_TEST_SERVICE_ACCOUNT_JSON  key of a service account that may only use that TEST key
 * Production's key and service account are never used here. Without the secrets the suite is
 * reported as skipped, never as passed. The same scenarios run on every CI run against an
 * emulator of Google's API (gcp-kms.emulated.test.ts).
 */
const KEY = process.env.GCP_TEST_KMS_KEY_NAME;
const SA = process.env.GCP_TEST_SERVICE_ACCOUNT_JSON;

defineKmsScenarios('Google Cloud KMS (live)', Boolean(KEY && SA), () => ({ key: KEY!, sa: SA! }));

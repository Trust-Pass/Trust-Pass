import type { AppConfig } from '../../config';
import { FakeKms } from './fake';
import { GcpKms, parseServiceAccount } from './gcp';
import type { KmsProvider } from './types';

export type { KmsProvider } from './types';
export { KmsError } from './types';

/** The KMS for KEY_PROVIDER, or null for the legacy `env` provider. */
export function createKmsProvider(config: AppConfig): KmsProvider | null {
  switch (config.env.KEY_PROVIDER) {
    case 'env':
      return null;
    case 'fake-kms':
      return new FakeKms({ keyFile: config.env.FAKE_KMS_KEY_FILE });
    case 'gcp-kms':
      return new GcpKms({
        keyName: config.env.GCP_KMS_KEY_NAME!,
        credentials: parseServiceAccount(config.env.GCP_SERVICE_ACCOUNT_JSON!),
      });
  }
}

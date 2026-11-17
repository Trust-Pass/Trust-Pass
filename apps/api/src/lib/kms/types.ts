/**
 * A key management service that protects TrustPass's key-encryption keys (KEKs).
 *
 * The root key lives inside the KMS and never leaves it. TrustPass only ever sends it
 * small 32-byte KEKs to encrypt (once, when a KEK is created) or decrypt (once per
 * start-up). Document keys are wrapped locally with the KEK, so KMS is not called per
 * document.
 */
export interface KmsProvider {
  readonly name: 'fake-kms' | 'gcp-kms';
  /** Resource name of the root key. Not secret; safe to log and to store next to the ciphertext. */
  readonly keyName: string;
  /** Encrypts key material. `aad` binds the ciphertext to its purpose and version. */
  encrypt(plaintext: Buffer, aad: string): Promise<Buffer>;
  /** Throws KmsError if the ciphertext, the AAD or the root key do not match. */
  decrypt(ciphertext: Buffer, aad: string): Promise<Buffer>;
}

export class KmsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KmsError';
  }
}

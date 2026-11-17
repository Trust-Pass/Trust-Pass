/**
 * A versioned set of 256-bit keys for one purpose. `current` encrypts new data;
 * every version in `all` can still decrypt older data.
 *
 * Keys protected by a KMS are only known after start-up (see lib/keyring.ts), so
 * reading `current` before then throws instead of silently using a wrong key.
 */
export interface MasterKey {
  version: number;
  key: Buffer;
}

export class KeySet {
  readonly all = new Map<number, Buffer>();
  private currentVersion: number | null = null;

  constructor(private readonly purpose: string) {}

  add(version: number, key: Buffer, options: { current?: boolean } = {}) {
    if (!Number.isInteger(version) || version < 1) throw new Error(`Invalid ${this.purpose} key version ${version}`);
    if (key.length !== 32) throw new Error(`${this.purpose} key version ${version} must be 32 bytes`);
    const existing = this.all.get(version);
    if (existing && !existing.equals(key)) {
      throw new Error(`Two different ${this.purpose} keys are configured as version ${version}`);
    }
    this.all.set(version, key);
    if (options.current) this.currentVersion = version;
  }

  setCurrent(version: number) {
    if (!this.all.has(version)) throw new Error(`${this.purpose} key version ${version} is not loaded`);
    this.currentVersion = version;
  }

  get hasCurrent(): boolean {
    return this.currentVersion !== null;
  }

  get current(): MasterKey {
    if (this.currentVersion === null) throw new Error(`Encryption keys (${this.purpose}) are not loaded yet`);
    return { version: this.currentVersion, key: this.all.get(this.currentVersion)! };
  }

  get versions(): number[] {
    return [...this.all.keys()].sort((a, b) => a - b);
  }
}

/** A stored item uses a key version this process has not loaded (e.g. created by a rotation after start-up). */
export class UnknownKeyVersionError extends Error {
  constructor(readonly version: number) {
    super(`Master key version ${version} is not configured`);
    this.name = 'UnknownKeyVersionError';
  }
}

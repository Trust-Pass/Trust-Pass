import { isIP } from 'node:net';
import maxmind, { type Reader, type Response } from 'maxmind';
import type { AppConfig } from '../config';

/**
 * Country lookup from an IP address. The result is approximate: VPNs,
 * proxies, mobile carriers and corporate gateways can all report the wrong
 * country. Returns null when the country cannot be determined.
 */
export interface GeoProvider {
  readonly name: 'mmdb' | 'simulated';
  lookup(ip: string): string | null;
}

interface CountryRecord {
  country_code?: string;
}

class MmdbGeoProvider implements GeoProvider {
  readonly name = 'mmdb' as const;
  constructor(private readonly reader: Reader<Response>) {}

  lookup(ip: string): string | null {
    const clean = normaliseIp(ip);
    if (!clean) return null;
    try {
      const code = (this.reader.get(clean) as CountryRecord | null)?.country_code;
      return code && /^[A-Z]{2}$/.test(code) ? code : null;
    } catch {
      return null;
    }
  }
}

/**
 * Test and local-development provider: maps chosen IPs to countries. It is
 * refused at startup in production (see loadConfig), so it cannot become a bypass.
 */
export class SimulatedGeoProvider implements GeoProvider {
  readonly name = 'simulated' as const;
  constructor(
    private readonly map: Map<string, string>,
    private readonly fallback: string | null,
  ) {}

  lookup(ip: string): string | null {
    const clean = normaliseIp(ip);
    if (!clean) return null;
    return this.map.get(clean) ?? this.fallback;
  }
}

function normaliseIp(ip: string): string | null {
  const trimmed = ip.trim().replace(/^::ffff:/, '');
  return isIP(trimmed) ? trimmed : null;
}

export function parseSimulatedMap(value: string | undefined): Map<string, string> {
  const map = new Map<string, string>();
  if (!value) return map;
  for (const pair of value.split(',')) {
    const [ip, code] = pair.split('=').map((s) => s.trim());
    if (ip && code && /^[A-Z]{2}$/.test(code)) map.set(ip, code);
  }
  return map;
}

export async function createGeoProvider(config: AppConfig): Promise<GeoProvider> {
  if (config.env.GEO_PROVIDER === 'simulated') {
    return new SimulatedGeoProvider(
      parseSimulatedMap(config.env.GEO_SIMULATED_MAP),
      config.env.GEO_SIMULATED_DEFAULT?.toUpperCase() ?? null,
    );
  }
  const reader = await maxmind.open<Response>(config.geoDbPath);
  return new MmdbGeoProvider(reader);
}

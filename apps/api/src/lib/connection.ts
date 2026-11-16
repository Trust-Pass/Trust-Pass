import { BlockList, isIP } from 'node:net';
import type { FastifyRequest } from 'fastify';
import type { GeoProvider } from './geo';

const internal = new BlockList();
internal.addSubnet('10.0.0.0', 8, 'ipv4');
internal.addSubnet('172.16.0.0', 12, 'ipv4');
internal.addSubnet('192.168.0.0', 16, 'ipv4');
internal.addSubnet('100.64.0.0', 10, 'ipv4');
internal.addSubnet('127.0.0.0', 8, 'ipv4');
internal.addSubnet('169.254.0.0', 16, 'ipv4');
internal.addSubnet('fc00::', 7, 'ipv6');
internal.addSubnet('fe80::', 10, 'ipv6');
internal.addAddress('::1', 'ipv6');

export type AddressKind = 'public' | 'private' | 'invalid';

export function addressKind(value: string): AddressKind {
  const ip = value.trim().replace(/^::ffff:/, '');
  const family = isIP(ip);
  if (!family) return 'invalid';
  return internal.check(ip, family === 4 ? 'ipv4' : 'ipv6') ? 'private' : 'public';
}

const PLATFORM_HEADERS = ['cf-connecting-ip', 'true-client-ip', 'x-real-ip', 'fly-client-ip', 'x-client-ip'];

/**
 * The configured edge header wins when it holds one valid address; otherwise
 * fall back to request.ip, which already honours TRUST_PROXY.
 */
export function resolveClientIp(request: FastifyRequest, header: string | null): string {
  if (header) {
    const value = request.headers[header];
    const candidate = (Array.isArray(value) ? value[0] : value)?.trim().replace(/^::ffff:/, '');
    if (candidate && isIP(candidate)) return candidate;
  }
  return request.ip;
}

/**
 * Describes how a request reached the server, for diagnosing geolocation
 * behind proxies. It never returns IP addresses, only their kind and country.
 */
export function describeConnection(request: FastifyRequest, geo: GeoProvider, clientIpHeader: string | null = null) {
  const forwarded = request.headers['x-forwarded-for'];
  const entries = (Array.isArray(forwarded) ? forwarded.join(',') : (forwarded ?? ''))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const chain = [
    ...entries.map((ip, i) => ({ position: `forwarded ${i + 1} of ${entries.length}`, kind: addressKind(ip), country: geo.lookup(ip) })),
    { position: 'direct connection', kind: addressKind(request.socket.remoteAddress ?? ''), country: null as string | null },
  ];
  return {
    approximateCountry: geo.lookup(request.clientIp),
    usedAddressKind: addressKind(request.clientIp),
    addressSource: clientIpHeader && request.clientIp !== request.ip ? clientIpHeader : 'x-forwarded-for / socket',
    proxyChainCountry: geo.lookup(request.ip),
    forwardedHops: entries.length,
    chain,
    platformHeadersPresent: PLATFORM_HEADERS.filter((h) => request.headers[h] !== undefined),
  };
}

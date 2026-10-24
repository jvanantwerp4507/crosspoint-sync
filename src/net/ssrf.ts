import net from 'node:net';
import { Agent, buildConnector, type Dispatcher } from 'undici';

/**
 * SSRF protection for outbound connector requests.
 *
 * Connectors fetch user-supplied server URLs (Audiobookshelf, kosync, OPDS, ...).
 * On a public / multi-user deployment that is a server-side request forgery
 * surface: a user can point a connector at an internal address and make the
 * server reach things it shouldn't (cloud metadata at 169.254.169.254, the
 * TrueNAS admin UI, other LAN services, localhost-only admin ports).
 *
 * The guard works at the TCP layer via a custom undici connector, so it covers
 * every case in one place:
 *   - the initial request AND every redirect hop (the connector runs per
 *     connection, whichever URL undici is following),
 *   - literal-IP hosts (http://10.0.0.1) - blocked before the socket opens,
 *   - hostnames that resolve to a private IP - blocked after connect by
 *     inspecting the socket's actual remoteAddress, which also closes the
 *     DNS-rebinding (TOCTOU) gap a pre-resolution check would leave open.
 *
 * Pure-LAN self-hosters who intentionally point connectors at a private
 * Audiobookshelf can opt out with ALLOW_PRIVATE_CONNECTOR_HOSTS=1. It is OFF by
 * default, which is the safe choice for any internet-facing instance.
 */

export class SsrfBlockedError extends Error {
  constructor(
    public readonly host: string,
    public readonly address: string
  ) {
    super(`Blocked request to private or reserved address ${address} (host ${host})`);
    this.name = 'SsrfBlockedError';
  }
}

/** Reserved / private / loopback / link-local ranges that connectors must not reach. */
function buildBlockList(): net.BlockList {
  const bl = new net.BlockList();
  // IPv4
  bl.addSubnet('0.0.0.0', 8, 'ipv4'); // "this" network
  bl.addSubnet('10.0.0.0', 8, 'ipv4'); // RFC1918 private
  bl.addSubnet('100.64.0.0', 10, 'ipv4'); // CGNAT (RFC6598)
  bl.addSubnet('127.0.0.0', 8, 'ipv4'); // loopback
  bl.addSubnet('169.254.0.0', 16, 'ipv4'); // link-local (incl. 169.254.169.254 metadata)
  bl.addSubnet('172.16.0.0', 12, 'ipv4'); // RFC1918 private
  bl.addSubnet('192.0.0.0', 24, 'ipv4'); // IETF protocol assignments
  bl.addSubnet('192.0.2.0', 24, 'ipv4'); // TEST-NET-1
  bl.addSubnet('192.168.0.0', 16, 'ipv4'); // RFC1918 private
  bl.addSubnet('198.18.0.0', 15, 'ipv4'); // benchmarking
  bl.addSubnet('198.51.100.0', 24, 'ipv4'); // TEST-NET-2
  bl.addSubnet('203.0.113.0', 24, 'ipv4'); // TEST-NET-3
  bl.addSubnet('224.0.0.0', 4, 'ipv4'); // multicast
  bl.addSubnet('240.0.0.0', 4, 'ipv4'); // reserved / future use
  bl.addAddress('255.255.255.255', 'ipv4'); // limited broadcast
  // IPv6
  bl.addAddress('::', 'ipv6'); // unspecified
  bl.addAddress('::1', 'ipv6'); // loopback
  bl.addSubnet('fc00::', 7, 'ipv6'); // unique local
  bl.addSubnet('fe80::', 10, 'ipv6'); // link-local
  bl.addSubnet('ff00::', 8, 'ipv6'); // multicast
  bl.addSubnet('2001:db8::', 32, 'ipv6'); // documentation
  bl.addSubnet('64:ff9b::', 96, 'ipv6'); // NAT64 (wraps IPv4; blocked defensively)
  bl.addSubnet('fd00:ec2::', 32, 'ipv6'); // AWS IMDS over IPv6
  return bl;
}

const BLOCK_LIST = buildBlockList();

/** Strip IPv6 brackets and unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) to plain IPv4. */
function normalizeIp(raw: string): { ip: string; type: 'ipv4' | 'ipv6' } | null {
  let ip = raw.trim();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  const fam = net.isIP(ip);
  if (fam === 4) return { ip, type: 'ipv4' };
  if (fam === 6) return { ip, type: 'ipv6' };
  return null;
}

/** True when an IP literal falls in a reserved/private range (unparseable -> blocked). */
export function isBlockedAddress(raw: string): boolean {
  const n = normalizeIp(raw);
  if (!n) return true;
  return BLOCK_LIST.check(n.ip, n.type);
}

/** Read the opt-out flag (default: block private hosts). */
export function allowPrivateHosts(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.ALLOW_PRIVATE_CONNECTOR_HOSTS;
  return v === '1' || v === 'true';
}

/**
 * Validate a URL before it is fetched: only http(s), and reject literal-IP hosts
 * that are private. Hostname-based hosts are checked at connect time by the
 * dispatcher below. Returns the parsed URL so callers can reuse it.
 */
export function assertAllowedUrl(urlStr: string, env: NodeJS.ProcessEnv = process.env): URL {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new SsrfBlockedError(urlStr, '(unparseable URL)');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfBlockedError(url.hostname || urlStr, `(unsupported scheme ${url.protocol})`);
  }
  if (!allowPrivateHosts(env)) {
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && isBlockedAddress(host)) {
      throw new SsrfBlockedError(host, host);
    }
  }
  return url;
}

/**
 * A custom undici connector that blocks reserved/private targets. Rejects
 * literal-IP hosts before connecting, and otherwise inspects the real
 * remoteAddress after connect (rebinding-safe).
 */
export function createSsrfConnector(allowPrivate: boolean): ReturnType<typeof buildConnector> {
  const base = buildConnector({});
  if (allowPrivate) return base;
  return ((options, callback) => {
    const host = String((options as { hostname?: string }).hostname ?? '').replace(/^\[|\]$/g, '');
    if (net.isIP(host) && isBlockedAddress(host)) {
      queueMicrotask(() => callback(new SsrfBlockedError(host, host), null));
      return;
    }
    base(options, (err, socket) => {
      if (err || !socket) {
        callback(err, socket ?? null);
        return;
      }
      const addr = socket.remoteAddress;
      if (addr && isBlockedAddress(addr)) {
        socket.destroy();
        callback(new SsrfBlockedError(host, addr), null);
        return;
      }
      callback(null, socket);
    });
  }) as ReturnType<typeof buildConnector>;
}

/** Build an undici Agent whose connections are SSRF-guarded. */
export function createSsrfAgent(allowPrivate: boolean): Agent {
  return new Agent({
    connect: createSsrfConnector(allowPrivate),
    // Bound per-request time so a slow/hostile remote can't pin a sync worker open.
    headersTimeout: 30_000,
    bodyTimeout: 60_000,
  });
}

let cachedDispatcher: Dispatcher | undefined;

/** Shared SSRF-guarded dispatcher, built once from the environment. */
export function ssrfDispatcher(): Dispatcher {
  if (!cachedDispatcher) cachedDispatcher = createSsrfAgent(allowPrivateHosts());
  return cachedDispatcher;
}

/** Test seam: drop the cached dispatcher so a changed env is picked up. */
export function resetSsrfDispatcherCache(): void {
  cachedDispatcher = undefined;
}

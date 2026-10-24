import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { fetch as undiciFetch } from 'undici';
import {
  isBlockedAddress,
  assertAllowedUrl,
  allowPrivateHosts,
  createSsrfAgent,
  SsrfBlockedError,
} from '../src/net/ssrf.js';

describe('isBlockedAddress', () => {
  it('blocks loopback, private, link-local and metadata ranges', () => {
    for (const ip of [
      '127.0.0.1',
      '127.9.9.9',
      '10.0.0.5',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata
      '100.64.0.1', // CGNAT
      '0.0.0.0',
      '::1',
      '::',
      'fe80::1', // link-local
      'fc00::1', // unique-local
      '::ffff:10.0.0.1', // IPv4-mapped private
      '[::1]', // bracketed
    ]) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it('allows ordinary public addresses', () => {
    expect(isBlockedAddress('1.1.1.1')).toBe(false);
    expect(isBlockedAddress('8.8.8.8')).toBe(false);
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false); // public IPv6
  });

  it('blocks unparseable input', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
    expect(isBlockedAddress('')).toBe(true);
  });
});

describe('assertAllowedUrl', () => {
  const block = {} as NodeJS.ProcessEnv; // ALLOW_PRIVATE unset -> block

  it('rejects non-http(s) schemes', () => {
    expect(() => assertAllowedUrl('file:///etc/passwd', block)).toThrow(SsrfBlockedError);
    expect(() => assertAllowedUrl('gopher://x/', block)).toThrow(SsrfBlockedError);
  });

  it('rejects literal private-IP hosts', () => {
    expect(() => assertAllowedUrl('http://169.254.169.254/latest/meta-data/', block)).toThrow(
      SsrfBlockedError
    );
    expect(() => assertAllowedUrl('http://127.0.0.1:9000/', block)).toThrow(SsrfBlockedError);
    expect(() => assertAllowedUrl('http://[::1]/', block)).toThrow(SsrfBlockedError);
  });

  it('allows public hosts and hostnames (resolution is checked at connect time)', () => {
    expect(assertAllowedUrl('https://api.audiobookshelf.org/api/me', block).hostname).toBe(
      'api.audiobookshelf.org'
    );
    expect(assertAllowedUrl('https://1.1.1.1/', block).hostname).toBe('1.1.1.1');
  });

  it('honors the ALLOW_PRIVATE_CONNECTOR_HOSTS escape hatch', () => {
    const allow = { ALLOW_PRIVATE_CONNECTOR_HOSTS: '1' } as unknown as NodeJS.ProcessEnv;
    expect(allowPrivateHosts(allow)).toBe(true);
    expect(() => assertAllowedUrl('http://192.168.1.50:13378/', allow)).not.toThrow();
  });
});

describe('SSRF-guarded dispatcher (real connections)', () => {
  it('blocks a real connection to a loopback server by default', async () => {
    const server = http.createServer((_req, res) => res.end('ok'));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as import('node:net').AddressInfo).port;
    try {
      const agent = createSsrfAgent(false);
      await expect(
        undiciFetch(`http://127.0.0.1:${port}/`, { dispatcher: agent })
      ).rejects.toThrow();
      await agent.close();
    } finally {
      server.close();
    }
  });

  it('allows the same connection when private hosts are permitted', async () => {
    const server = http.createServer((_req, res) => res.end('ok'));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as import('node:net').AddressInfo).port;
    try {
      const agent = createSsrfAgent(true);
      const res = await undiciFetch(`http://127.0.0.1:${port}/`, { dispatcher: agent });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe('ok');
      await agent.close();
    } finally {
      server.close();
    }
  });
});

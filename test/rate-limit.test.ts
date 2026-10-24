import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { rateLimiter } from '../src/auth/middleware.js';
import type { AppEnv } from '../src/auth/middleware.js';

function appWith(limit: number, trustProxy: boolean) {
  const app = new Hono<AppEnv>();
  app.post('/x', rateLimiter(limit, trustProxy), (c) => c.text('ok'));
  return app;
}

/** Hono test request: 3rd arg is the Bindings env (sets c.env.incoming.socket). */
function call(app: Hono<AppEnv>, opts: { xff?: string; remote: string }) {
  const headers: Record<string, string> = {};
  if (opts.xff) headers['x-forwarded-for'] = opts.xff;
  return app.request(
    '/x',
    { method: 'POST', headers },
    { incoming: { socket: { remoteAddress: opts.remote } } }
  );
}

describe('rateLimiter IP keying', () => {
  it('ignores X-Forwarded-For when the proxy is not trusted (spoofing cannot dodge the limit)', async () => {
    const app = appWith(2, false);
    // Same socket, different spoofed XFF each time -> all count against one bucket.
    const r1 = await call(app, { xff: '1.1.1.1', remote: '9.9.9.9' });
    const r2 = await call(app, { xff: '2.2.2.2', remote: '9.9.9.9' });
    const r3 = await call(app, { xff: '3.3.3.3', remote: '9.9.9.9' });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r3.status).toBe(429);
  });

  it('separates distinct real sockets', async () => {
    const app = appWith(1, false);
    expect((await call(app, { remote: '9.9.9.9' })).status).toBe(200);
    expect((await call(app, { remote: '9.9.9.9' })).status).toBe(429);
    // A genuinely different client is unaffected.
    expect((await call(app, { remote: '8.8.8.8' })).status).toBe(200);
  });

  it('honors X-Forwarded-For when behind a trusted proxy', async () => {
    const app = appWith(2, true);
    // Distinct forwarded clients each get their own bucket despite one socket.
    expect((await call(app, { xff: '1.1.1.1', remote: '10.0.0.1' })).status).toBe(200);
    expect((await call(app, { xff: '2.2.2.2', remote: '10.0.0.1' })).status).toBe(200);
    expect((await call(app, { xff: '3.3.3.3', remote: '10.0.0.1' })).status).toBe(200);
    // Same forwarded client is limited.
    expect((await call(app, { xff: '7.7.7.7', remote: '10.0.0.1' })).status).toBe(200);
    expect((await call(app, { xff: '7.7.7.7', remote: '10.0.0.1' })).status).toBe(200);
    expect((await call(app, { xff: '7.7.7.7', remote: '10.0.0.1' })).status).toBe(429);
  });
});

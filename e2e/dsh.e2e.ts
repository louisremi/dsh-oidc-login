/**
 * End-to-end check against a real `dsh web` (the dsh on PATH): boots it with
 * this plugin and a mock OpenID Provider, then walks the browser flow.
 *
 *   npm run build && node e2e/dsh.e2e.ts
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { MockProvider } from '../test/helpers.ts';

const port = Number(process.env.E2E_PORT ?? 3191);
const origin = `http://127.0.0.1:${port}`;
const work = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'oidc-e2e-'));
const home = join(work, 'home');
mkdirSync(home);
writeFileSync(join(work, 'secret'), 'client-secret\n');
const patch = join(work, 'patch.yml');
writeFileSync(
  patch,
  `- insert:\n    - id: oidc-login\n      name: '${resolve('dist/index.js')}'\n- id: webserver\n  name: '@deepseek-ai/dsh-host-webserver'\n  config:\n    host: '127.0.0.1'\n    port: ${port}\n`,
);

const provider = await new MockProvider().start();
const child = spawn('dsh', ['web', '--patch', patch, '--no-open', '--port', String(port)], {
  env: {
    ...process.env,
    DSH_HOME: home,
    HOME: work,
    DSH_TELEMETRY_DISABLED: '1',
    DSH_OIDC_ISSUER: provider.issuer,
    DSH_OIDC_CLIENT_ID: 'dsh',
    DSH_OIDC_CLIENT_SECRET_FILE: join(work, 'secret'),
    DSH_OIDC_PUBLIC_URL: origin,
    DSH_OIDC_ALLOWED_EMAILS: 'owner@example.com',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
child.stdout.on('data', (d) => {
  output += d;
});
child.stderr.on('data', (d) => {
  output += d;
});

const nav = { accept: 'text/html', 'sec-fetch-mode': 'navigate' };
interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  text: () => Promise<string>;
}
// node:http rather than fetch: undici forces `sec-fetch-mode: cors`, a browser navigation sends `navigate`.
const get = (path: string, headers: Record<string, string> = {}): Promise<Reply> =>
  new Promise((done, fail) => {
    const req = request(`${origin}${path}`, { headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () =>
        done({ status: res.statusCode ?? 0, headers: res.headers, text: async () => body }),
      );
    });
    req.on('error', fail);
    req.end();
  });
const location = (res: Reply) => String(res.headers.location ?? '');
const pair = (res: Reply, name: string) => {
  const raw = res.headers['set-cookie'] ?? [];
  return (Array.isArray(raw) ? raw : [raw])
    .map((c) => c.split(';')[0] ?? '')
    .find((c) => c.startsWith(name));
};

try {
  for (let i = 0; ; i++) {
    if (output.includes('dsh web: http')) break;
    if (child.exitCode !== null || i > 120) throw new Error(`dsh web did not start:\n${output}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  // dsh routes plugin logs through its own logger (not stdout).

  // Unauthenticated: API-style 401 unchanged, browser navigation redirected.
  assert.equal((await get('/')).status, 401);
  const redirect = await get('/', nav);
  assert.equal(redirect.status, 302);
  assert.equal(location(redirect), '/auth/login');

  // Sign in.
  const login = await get('/auth/login', nav);
  assert.equal(login.status, 302);
  const state = pair(login, 'dsh-oidc-state=');
  assert.ok(state);
  const callback = new URL(provider.approve(location(login)));
  const done = await get(`${callback.pathname}${callback.search}`, { ...nav, cookie: state });
  assert.equal(done.status, 303, await done.text());
  const session = pair(done, 'dsh-auth-');
  assert.ok(session, 'dsh session cookie');

  // The real dsh accepts the minted cookie: index and /api.
  const index = await get('/', { ...nav, cookie: session });
  assert.equal(index.status, 200);
  assert.match(await index.text(), /<html/iu);
  const api = await get('/api/download.file', { cookie: session });
  assert.notEqual(api.status, 401, 'dsh /api accepts the cookie');
  assert.equal((await get('/api/download.file')).status, 401);

  // The launch-token link still works.
  const token = /dsh web: (\S+)/u.exec(output)?.[1] ?? '';
  const tokenUrl = new URL(token);
  const viaToken = await get(`/?token=${tokenUrl.searchParams.get('token')}`, nav);
  assert.equal(viaToken.status, 303);
  assert.ok(pair(viaToken, 'dsh-auth-'));

  console.log('e2e: ok');
} catch (error) {
  console.error(output);
  throw error;
} finally {
  child.kill('SIGTERM');
  await provider.stop();
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Admission, AdmissionRequest, PluginContext, RequestLike } from '../src/context.ts';
import { type CapturedResponse, resolveDshAuth } from '../src/dsh-auth.ts';
import { fakeConnection, LAUNCH_TOKEN } from './helpers.ts';

type Listener = (...args: any[]) => unknown;

/**
 * A fake of dsh 0.2.3's Token Provider, wired the way the real one is: it
 * announces its signed URL on `webserver/entry-url`, exchanges `/?token=` in
 * `webserver/request` (calling `next()` for anything else), and WebServer's
 * `authorize` admits a request carrying the cookie it minted.
 */
function tokenProviderCtx(options: { announce?: boolean } = {}) {
  const listeners = new Map<string, Listener[]>();
  const on = (name: string, listener: Listener) => {
    listeners.set(name, [...(listeners.get(name) ?? []), listener]);
  };
  const minted: string[] = [];
  const browserPeer = { kind: 'owner' };
  const cookieFor = (host: string) => `dsh-auth-x=cookie-for-${host}`;
  if (options.announce !== false) {
    on('webserver/entry-url', (base: string, entries: { label: string; url: string }[]) => {
      const url = new URL(base);
      url.searchParams.set('token', LAUNCH_TOKEN);
      entries.push({ label: 'dsh web', url: url.href });
    });
  }
  on('webserver/request', (req: RequestLike, res: CapturedResponse, next: () => unknown) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (url.pathname !== '/' || !url.searchParams.has('token')) return next();
    const host = req.headers.host as string | undefined;
    if (url.searchParams.get('token') === LAUNCH_TOKEN && host) {
      minted.push(host);
      res.writeHead(303, {
        location: './',
        'set-cookie': `${cookieFor(host)}; Path=/; HttpOnly; SameSite=Lax`,
      });
      res.end();
      return;
    }
    res.writeHead(401);
    res.end('unauthorized');
  });
  const authorizeCalls: AdmissionRequest[] = [];
  const ctx: PluginContext = {
    connection: { browserPeer },
    webServer: {
      register: () => () => {},
      readResource: async () => new Response(null),
      authorize(request): Admission {
        authorizeCalls.push(request);
        const host = request.headers.host as string | undefined;
        const cookie = (request.headers.cookie as string | undefined) ?? '';
        return host !== undefined && cookie.includes(cookieFor(host))
          ? { kind: 'allow', peer: browserPeer }
          : { kind: 'deny', status: 401 };
      },
    },
    effect: () => undefined,
    emit(_thisArg, name, ...args) {
      for (const listener of listeners.get(name) ?? []) listener(...args);
    },
    waterfall(_thisArg, name, ...args) {
      const inner = args.pop() as () => unknown;
      const chain = [...(listeners.get(name) ?? [])];
      const dispatch = (): unknown => {
        const listener = chain.shift();
        return listener === undefined ? inner() : listener(...args, dispatch);
      };
      return dispatch();
    },
  };
  return { ctx, minted, browserPeer, authorizeCalls };
}

test('dsh 0.2.2 (connection.authorizeIndex): the legacy adapter is used', async () => {
  const connection = fakeConnection();
  const auth = resolveDshAuth({
    connection,
    webServer: { register: () => () => {}, readResource: async () => new Response(null) },
    effect: () => undefined,
    emit: () => {},
    waterfall: () => undefined,
  });
  assert.ok(auth);
  const minted = await auth.mintSessionCookie('dsh.example');
  assert.equal(minted.status, 303);
  assert.deepEqual(connection.minted, ['cookie-for-dsh.example']);
});

test('dsh 0.2.3: mints the session cookie through the Token Provider, for the given host', async () => {
  const { ctx, minted } = tokenProviderCtx();
  const auth = resolveDshAuth(ctx);
  assert.ok(auth);
  const reply = await auth.mintSessionCookie('dsh.example');
  assert.equal(reply.status, 303);
  assert.match(String(reply.headers['set-cookie']), /^dsh-auth-x=cookie-for-dsh\.example;/u);
  assert.deepEqual(minted, ['dsh.example']);
});

test('dsh 0.2.3: no announced login URL means no cookie (fails closed)', async () => {
  const { ctx, minted } = tokenProviderCtx({ announce: false });
  const auth = resolveDshAuth(ctx);
  assert.ok(auth);
  const reply = await auth.mintSessionCookie('dsh.example');
  assert.notEqual(reply.status, 303);
  assert.equal(reply.headers['set-cookie'], undefined);
  assert.deepEqual(minted, []);
});

test('dsh 0.2.3: the index decision is WebServer admission for a required route', async () => {
  const { ctx, browserPeer, authorizeCalls } = tokenProviderCtx();
  const auth = resolveDshAuth(ctx);
  assert.ok(auth);
  assert.equal(auth.browserPeer, browserPeer);
  const anonymous = await auth.authorizeIndex({
    method: 'GET',
    url: '/',
    headers: { host: 'dsh.example' },
  });
  assert.equal(anonymous.authorized, false);
  assert.equal(anonymous.reply.status, 401);
  const withCookie = await auth.authorizeIndex({
    method: 'GET',
    url: '/',
    headers: { host: 'dsh.example', cookie: 'dsh-auth-x=cookie-for-dsh.example' },
  });
  assert.equal(withCookie.authorized, true);
  assert.equal(authorizeCalls[0]?.url.pathname, '/');
  assert.equal(authorizeCalls[0]?.transport, 'http');
});

test('dsh 0.2.3: a token link on / is answered by dsh exchange, unchanged', async () => {
  const { ctx, minted } = tokenProviderCtx();
  const auth = resolveDshAuth(ctx);
  assert.ok(auth);
  const good = await auth.authorizeIndex({
    method: 'GET',
    url: `/?token=${LAUNCH_TOKEN}`,
    headers: { host: 'dsh.example' },
  });
  assert.equal(good.authorized, false);
  assert.equal(good.reply.status, 303);
  assert.deepEqual(minted, ['dsh.example']);
  const bad = await auth.authorizeIndex({
    method: 'GET',
    url: '/?token=nope',
    headers: { host: 'dsh.example' },
  });
  assert.equal(bad.reply.status, 401);
});

test('neither API: no adapter', () => {
  const auth = resolveDshAuth({
    connection: { browserPeer: {} },
    webServer: { register: () => () => {}, readResource: async () => new Response(null) },
    effect: () => undefined,
    emit: () => {},
    waterfall: () => undefined,
  });
  assert.equal(auth, undefined);
});

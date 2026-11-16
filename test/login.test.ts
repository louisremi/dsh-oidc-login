import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { after, before, test } from 'node:test';
import { OidcClient } from '../src/oidc.ts';
import { LoginRoutes } from '../src/routes.ts';
import {
  call,
  config,
  cookiePair,
  fakeConnection,
  MockProvider,
  setCookies,
  silentLogger,
} from './helpers.ts';

const HOST = { host: 'dsh.example' };
let provider: MockProvider;

before(async () => {
  provider = await new MockProvider().start();
});
after(() => provider.stop());

function setup(overrides: Parameters<typeof config>[0] = {}) {
  const connection = fakeConnection();
  const logger = silentLogger();
  const cfg = config({ issuer: provider.issuer, ...overrides });
  const indexReads: Request[] = [];
  const routes = new LoginRoutes({
    config: cfg,
    oidc: new OidcClient(cfg.issuer, cfg.clientId, cfg.clientSecret),
    connection,
    webServer: {
      async readResource(request) {
        indexReads.push(request);
        return new Response('<html>dsh</html>', { headers: { 'content-type': 'text/html' } });
      },
    },
    logger,
  });
  return { routes, connection, logger, indexReads };
}

/** Run /auth/login, approve at the provider, return the callback request inputs. */
async function startLogin(routes: LoginRoutes) {
  const login = await call(routes.login, { path: '/auth/login', headers: HOST });
  assert.equal(login.status, 302);
  const stateCookie = cookiePair(setCookies(login.headers)[0] ?? '');
  assert.match(stateCookie, /^dsh-oidc-state=.+/u);
  const callbackUrl = new URL(provider.approve(String(login.headers.location)));
  return {
    stateCookie,
    path: `${callbackUrl.pathname}${callbackUrl.search}`,
    location: String(login.headers.location),
  };
}

test('login redirects to the provider with PKCE S256, state and nonce', async () => {
  const { routes } = setup();
  const { location, stateCookie } = await startLogin(routes);
  const url = new URL(location);
  assert.equal(url.origin + url.pathname, `${provider.issuer}/authorize`);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), 'dsh');
  assert.equal(url.searchParams.get('redirect_uri'), 'https://dsh.example/auth/callback');
  assert.equal(url.searchParams.get('scope'), 'openid email profile');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('nonce'));
  assert.equal(`dsh-oidc-state=${url.searchParams.get('state')}`, stateCookie);
});

test('a full login for the allowed e-mail gets the dsh session cookie, minted for the request host', async () => {
  const { routes, connection } = setup();
  const { stateCookie, path } = await startLogin(routes);
  const res = await call(routes.callback, { path, headers: { ...HOST, cookie: stateCookie } });
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/');
  const cookies = setCookies(res.headers);
  assert.ok(cookies.some((c) => c.startsWith('dsh-auth-x=cookie-for-dsh.example')));
  assert.ok(cookies.some((c) => c.startsWith('dsh-oidc-state=;') && c.includes('Max-Age=0')));
  assert.deepEqual(connection.minted, ['cookie-for-dsh.example']);
  assert.equal(provider.tokenRequests.at(-1)?.get('grant_type'), 'authorization_code');
  assert.ok(provider.tokenRequests.at(-1)?.get('code_verifier'));
});

test('the e-mail allow-list is enforced case-insensitively', async () => {
  const { routes, connection } = setup({ allowedEmails: new Set(['owner@example.com']) });
  provider.email = 'Owner@Example.COM';
  try {
    const ok = await startLogin(routes);
    assert.equal(
      (await call(routes.callback, { path: ok.path, headers: { ...HOST, cookie: ok.stateCookie } }))
        .status,
      303,
    );
    provider.email = 'intruder@example.com';
    const bad = await startLogin(routes);
    const res = await call(routes.callback, {
      path: bad.path,
      headers: { ...HOST, cookie: bad.stateCookie },
    });
    assert.equal(res.status, 403);
    assert.equal(connection.minted.length, 1);
  } finally {
    provider.email = 'owner@example.com';
  }
});

test('an explicitly unverified e-mail is refused', async () => {
  const { routes } = setup();
  provider.emailVerified = false;
  try {
    const flow = await startLogin(routes);
    const res = await call(routes.callback, {
      path: flow.path,
      headers: { ...HOST, cookie: flow.stateCookie },
    });
    assert.equal(res.status, 403);
  } finally {
    provider.emailVerified = true;
  }
});

test('state must match the browser cookie and can be used only once', async () => {
  const { routes, connection } = setup();
  const flow = await startLogin(routes);
  // No cookie: login CSRF attempt.
  assert.equal((await call(routes.callback, { path: flow.path, headers: HOST })).status, 403);
  // Another browser's state cookie.
  const other = await startLogin(routes);
  assert.equal(
    (
      await call(routes.callback, {
        path: flow.path,
        headers: { ...HOST, cookie: other.stateCookie },
      })
    ).status,
    403,
  );
  // The state was consumed by the failed attempt above? No: mismatch does not consume. Correct pair works once.
  const first = await call(routes.callback, {
    path: other.path,
    headers: { ...HOST, cookie: other.stateCookie },
  });
  assert.equal(first.status, 303);
  const replay = await call(routes.callback, {
    path: other.path,
    headers: { ...HOST, cookie: other.stateCookie },
  });
  assert.equal(replay.status, 403);
  assert.equal(connection.minted.length, 1);
});

test('ID token checks: wrong issuer, audience, nonce, expiry and signature are all refused', async () => {
  const cases: Array<[string, (claims: Record<string, unknown>) => void]> = [
    [
      'iss',
      (c) => {
        c.iss = 'https://evil.example';
      },
    ],
    [
      'aud',
      (c) => {
        c.aud = ['someone-else'];
      },
    ],
    [
      'azp',
      (c) => {
        c.aud = ['dsh', 'other'];
        c.azp = 'other';
      },
    ],
    [
      'nonce',
      (c) => {
        c.nonce = 'forged';
      },
    ],
    [
      'exp',
      (c) => {
        c.exp = Math.floor(Date.now() / 1000) - 3600;
      },
    ],
    [
      'iat',
      (c) => {
        c.iat = Math.floor(Date.now() / 1000) + 3600;
      },
    ],
  ];
  for (const [label, tamper] of cases) {
    const { routes, connection } = setup();
    provider.tamper = tamper;
    try {
      const flow = await startLogin(routes);
      const res = await call(routes.callback, {
        path: flow.path,
        headers: { ...HOST, cookie: flow.stateCookie },
      });
      assert.equal(res.status, 403, label);
      assert.equal(connection.minted.length, 0, label);
    } finally {
      provider.tamper = () => {};
    }
  }
  const { routes, connection } = setup();
  provider.signWith = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  try {
    const flow = await startLogin(routes);
    const res = await call(routes.callback, {
      path: flow.path,
      headers: { ...HOST, cookie: flow.stateCookie },
    });
    assert.equal(res.status, 403, 'signature');
    assert.equal(connection.minted.length, 0);
  } finally {
    provider.signWith = undefined;
  }
});

test('a provider error on the callback is refused', async () => {
  const { routes } = setup();
  const flow = await startLogin(routes);
  const path = flow.path.replace(/code=[^&]+/u, 'error=access_denied');
  assert.equal(
    (await call(routes.callback, { path, headers: { ...HOST, cookie: flow.stateCookie } })).status,
    403,
  );
});

test('sign-in only works under the configured public host', async () => {
  const { routes } = setup();
  assert.equal(
    (await call(routes.login, { path: '/auth/login', headers: { host: 'other.example' } })).status,
    403,
  );
  const flow = await startLogin(routes);
  const res = await call(routes.callback, {
    path: flow.path,
    headers: { host: 'other.example', cookie: flow.stateCookie },
  });
  assert.equal(res.status, 403);
});

test('an unreachable provider gives a 503 page that points to the token link', async () => {
  const { routes } = setup({ issuer: 'http://127.0.0.1:9' });
  const res = await call(routes.login, { path: '/auth/login', headers: HOST });
  assert.equal(res.status, 503);
  assert.match(res.body, /token/u);
});

test('logout clears the dsh cookie for this host and ends the provider session', async () => {
  const { routes } = setup();
  const res = await call(routes.logout, { path: '/auth/logout', headers: HOST });
  assert.equal(res.status, 303);
  const location = new URL(String(res.headers.location));
  assert.equal(location.pathname, '/logout');
  assert.equal(
    location.searchParams.get('post_logout_redirect_uri'),
    'https://dsh.example/auth/login',
  );
  const [cookie] = setCookies(res.headers);
  assert.match(cookie ?? '', /^dsh-auth-[A-Za-z0-9_-]+=; Max-Age=0; Path=\//u);
});

test('root: a browser navigation without a session goes to the sign-in page', async () => {
  const { routes } = setup();
  const res = await call(routes.root, {
    path: '/',
    headers: { ...HOST, accept: 'text/html', 'sec-fetch-mode': 'navigate' },
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.location, '/auth/login');
});

test('root: API clients and health checks still get dsh 401; token links still work', async () => {
  const { routes, connection } = setup();
  const curl = await call(routes.root, { path: '/', headers: HOST });
  assert.equal(curl.status, 401);
  assert.match(curl.body, /authentication required/u);
  const fetchLike = await call(routes.root, {
    path: '/',
    headers: { ...HOST, accept: 'text/html', 'sec-fetch-mode': 'cors' },
  });
  assert.equal(fetchLike.status, 401);
  const token = await call(routes.root, {
    path: '/?token=launch-token-abc',
    headers: { ...HOST, accept: 'text/html' },
  });
  assert.equal(token.status, 303);
  assert.equal(connection.minted.length, 1);
  const wrong = await call(routes.root, {
    path: '/?token=nope',
    headers: { ...HOST, accept: 'text/html' },
  });
  assert.equal(wrong.status, 401);
});

test('root: other hosts (e.g. the LAN address) are not redirected', async () => {
  const { routes } = setup();
  const res = await call(routes.root, {
    path: '/',
    headers: { host: '10.0.0.5:3080', accept: 'text/html' },
  });
  assert.equal(res.status, 401);
});

test('root: an authenticated browser gets dsh index through readResource', async () => {
  const { routes, indexReads } = setup();
  const res = await call(routes.root, {
    path: '/',
    headers: { ...HOST, accept: 'text/html', cookie: 'dsh-auth-x=cookie-for-dsh.example' },
  });
  assert.equal(res.status, 200);
  assert.equal(res.body, '<html>dsh</html>');
  assert.equal(new URL(indexReads[0]?.url ?? '').pathname, '/index.html');
});

test('root: other methods are rejected', async () => {
  const { routes } = setup();
  assert.equal((await call(routes.root, { path: '/', method: 'POST', headers: HOST })).status, 405);
});

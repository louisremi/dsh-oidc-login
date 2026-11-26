import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { resolveConfig } from '../src/config.ts';
import type { AuthenticationProvider, CredentialStore } from '../src/context.ts';
import { apply } from '../src/index.ts';
import { fakeCredentials, silentLogger } from './helpers.ts';

const dir = mkdtempSync(join(tmpdir(), 'oidc-login-'));
const secretFile = join(dir, 'secret');
writeFileSync(secretFile, 'file-secret\n');

const base = {
  DSH_OIDC_ISSUER: 'https://auth.example',
  DSH_OIDC_CLIENT_ID: 'dsh',
  DSH_OIDC_CLIENT_SECRET_FILE: secretFile,
  DSH_OIDC_PUBLIC_URL: 'https://dsh.example/',
  DSH_OIDC_ALLOWED_EMAILS: 'Owner@Example.com, second@example.com',
};

test('disabled without an issuer', () => {
  assert.equal(resolveConfig(undefined, {}).kind, 'disabled');
});

test('resolves from the environment', () => {
  const result = resolveConfig(undefined, { ...base });
  assert.equal(result.kind, 'enabled');
  if (result.kind !== 'enabled') return;
  assert.equal(result.config.issuer, 'https://auth.example');
  assert.equal(result.config.clientSecret, 'file-secret');
  assert.equal(result.config.publicUrl, 'https://dsh.example');
  assert.deepEqual([...result.config.allowedEmails], ['owner@example.com', 'second@example.com']);
  assert.equal(result.config.sessionDays, 30);
  assert.deepEqual(result.warnings, []);
});

test('fails closed on an empty allow-list', () => {
  const result = resolveConfig(undefined, { ...base, DSH_OIDC_ALLOWED_EMAILS: ' , ' });
  assert.equal(result.kind, 'invalid');
});

test('requires https for remote issuers, allows loopback http for tests', () => {
  assert.equal(
    resolveConfig(undefined, { ...base, DSH_OIDC_ISSUER: 'http://auth.example' }).kind,
    'invalid',
  );
  assert.equal(
    resolveConfig(undefined, { ...base, DSH_OIDC_ISSUER: 'http://127.0.0.1:9091' }).kind,
    'enabled',
  );
});

test('the public URL must be an origin', () => {
  assert.equal(
    resolveConfig(undefined, { ...base, DSH_OIDC_PUBLIC_URL: 'https://dsh.example/sub' }).kind,
    'invalid',
  );
});

test('an inline secret is accepted and always removed from the environment', () => {
  const env: Record<string, string | undefined> = {
    ...base,
    DSH_OIDC_CLIENT_SECRET_FILE: undefined,
    DSH_OIDC_CLIENT_SECRET: 'inline',
  };
  const result = resolveConfig(undefined, env);
  assert.equal(result.kind, 'enabled');
  assert.equal(result.kind === 'enabled' && result.config.clientSecret, 'inline');
  assert.equal('DSH_OIDC_CLIENT_SECRET' in env, false);
  const disabledEnv: Record<string, string | undefined> = { DSH_OIDC_CLIENT_SECRET: 'leftover' };
  resolveConfig(undefined, disabledEnv);
  assert.equal('DSH_OIDC_CLIENT_SECRET' in disabledEnv, false);
});

test('email verification is required by default and can be turned off', () => {
  const strict = resolveConfig(undefined, { ...base });
  assert.equal(strict.kind === 'enabled' && strict.config.requireVerifiedEmail, true);
  const relaxed = resolveConfig(undefined, { ...base, DSH_OIDC_REQUIRE_VERIFIED_EMAIL: '0' });
  assert.equal(relaxed.kind === 'enabled' && relaxed.config.requireVerifiedEmail, false);
});

test('DSH_OIDC_REDIRECT_ROOT is ignored since 0.3.0, with a warning', () => {
  const result = resolveConfig(undefined, { ...base, DSH_OIDC_REDIRECT_ROOT: '0' });
  assert.equal(result.kind, 'enabled');
  assert.match(result.kind === 'enabled' ? result.warnings.join() : '', /ignored since 0\.3\.0/u);
});

test('DSH_OIDC_SESSION_DAYS accepts whole days from 1 to 365', () => {
  const week = resolveConfig(undefined, { ...base, DSH_OIDC_SESSION_DAYS: '7' });
  assert.equal(week.kind === 'enabled' && week.config.sessionDays, 7);
  for (const bad of ['0', '366', '1.5', 'x', '-1']) {
    assert.equal(
      resolveConfig(undefined, { ...base, DSH_OIDC_SESSION_DAYS: bad }).kind,
      'invalid',
      bad,
    );
  }
});

function fakeCtx(credentials: CredentialStore = fakeCredentials()) {
  const routes: string[] = [];
  const auths: (string | undefined)[] = [];
  const providers: AuthenticationProvider[] = [];
  const logger = silentLogger();
  const peer = { kind: 'owner-peer' };
  return {
    routes,
    auths,
    providers,
    peer,
    logger,
    ctx: {
      connection: {
        createPeer: () => peer,
        authentication: {
          register(provider: AuthenticationProvider) {
            providers.push(provider);
            return async () => {};
          },
        },
      },
      credentials,
      logger,
      webServer: {
        register(route: { path: string; auth?: string }) {
          routes.push(route.path);
          auths.push(route.auth);
          return () => {};
        },
      },
      effect(callback: () => unknown) {
        return callback();
      },
    },
  };
}

const configured = () => ({
  issuer: 'http://127.0.0.1:9',
  clientId: 'dsh',
  clientSecretFile: secretFile,
  publicUrl: 'https://dsh.example',
  allowedEmails: ['owner@example.com'],
});

test('apply registers nothing when not configured, and says so', async () => {
  const { ctx, routes, providers, logger } = fakeCtx();
  const saved = process.env.DSH_OIDC_ISSUER;
  delete process.env.DSH_OIDC_ISSUER;
  try {
    await apply(ctx);
  } finally {
    if (saved !== undefined) process.env.DSH_OIDC_ISSUER = saved;
  }
  assert.deepEqual(routes, ['/auth/status']);
  assert.equal(providers.length, 0);
  assert.match(logger.lines.join('\n'), /oidc-login: not configured/u);
});

test('apply registers nothing and logs an error when the config is invalid', async () => {
  const { ctx, routes, providers, logger } = fakeCtx();
  await apply(ctx, { ...configured(), allowedEmails: [] });
  assert.deepEqual(routes, ['/auth/status']);
  assert.equal(providers.length, 0);
  assert.match(logger.lines.join('\n'), /disabled, configuration is invalid: .*ALLOWED_EMAILS/u);
});

test('apply registers the anonymous sign-in routes and one provider, never "/"', async () => {
  const { ctx, routes, auths, providers } = fakeCtx();
  await apply(ctx, configured());
  assert.deepEqual(routes.sort(), [
    '/auth/callback',
    '/auth/login',
    '/auth/logout',
    '/auth/status',
  ]);
  assert.deepEqual(new Set(auths), new Set(['anonymous']));
  assert.equal(providers.length, 1);
});

test('the provider returns the owner Peer only for a valid session cookie', async () => {
  const credentials = fakeCredentials();
  const { ctx, providers, peer } = fakeCtx(credentials);
  await apply(ctx, configured());
  const { BrowserSessions, loadSigningKey } = await import('../src/session.ts');
  const sessions = new BrowserSessions(await loadSigningKey(credentials), {
    publicUrl: 'https://dsh.example',
    sessionDays: 30,
    allowedEmails: new Set(['owner@example.com']),
  });
  const cookie = sessions.issue('owner@example.com').split(';')[0] ?? '';
  const provider = providers[0];
  assert.ok(provider);
  assert.equal(provider.authenticate({ headers: { host: 'dsh.example', cookie } }), peer);
  assert.equal(provider.authenticate({ headers: { host: 'dsh.example' } }), undefined);
  assert.equal(provider.authenticate({ headers: { host: 'other.example', cookie } }), undefined);
});

test('apply fails closed when the signing key record is corrupt', async () => {
  const { ctx, routes, providers, logger } = fakeCtx(
    fakeCredentials({ kind: 'grant', payload: { version: 1, secret: 'short' } }),
  );
  await apply(ctx, configured());
  assert.deepEqual(routes, ['/auth/status']);
  assert.equal(providers.length, 0);
  assert.match(logger.lines.join('\n'), /cannot load the oidc-login\/browser-session signing key/u);
});

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { resolveConfig } from '../src/config.ts';
import { apply } from '../src/index.ts';
import { fakeConnection, silentLogger } from './helpers.ts';

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
  assert.equal(result.config.redirectRoot, true);
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

test('DSH_OIDC_REDIRECT_ROOT=0 turns the root redirect off', () => {
  const result = resolveConfig(undefined, { ...base, DSH_OIDC_REDIRECT_ROOT: '0' });
  assert.equal(result.kind === 'enabled' && result.config.redirectRoot, false);
});

function fakeCtx() {
  const routes: string[] = [];
  const logger = silentLogger();
  return {
    routes,
    logger,
    ctx: {
      connection: fakeConnection(),
      logger,
      webServer: {
        register(route: { path: string }) {
          routes.push(route.path);
          return () => {};
        },
        readResource: async () => new Response(null),
      },
      effect(callback: () => unknown) {
        return callback();
      },
    },
  };
}

test('apply registers nothing when not configured, and says so', () => {
  const { ctx, routes, logger } = fakeCtx();
  const saved = process.env.DSH_OIDC_ISSUER;
  delete process.env.DSH_OIDC_ISSUER;
  try {
    apply(ctx);
  } finally {
    if (saved !== undefined) process.env.DSH_OIDC_ISSUER = saved;
  }
  assert.deepEqual(routes, ['/auth/status']);
  assert.match(logger.lines.join('\n'), /oidc-login: not configured/u);
});

test('apply registers nothing and logs an error when the config is invalid', () => {
  const { ctx, routes, logger } = fakeCtx();
  apply(ctx, {
    issuer: 'https://auth.example',
    clientId: 'dsh',
    clientSecretFile: secretFile,
    publicUrl: 'https://dsh.example',
    allowedEmails: [],
  });
  assert.deepEqual(routes, ['/auth/status']);
  assert.match(logger.lines.join('\n'), /disabled, configuration is invalid: .*ALLOWED_EMAILS/u);
});

test('apply registers the sign-in routes when configured', () => {
  const { ctx, routes } = fakeCtx();
  apply(ctx, {
    issuer: 'http://127.0.0.1:9',
    clientId: 'dsh',
    clientSecretFile: secretFile,
    publicUrl: 'https://dsh.example',
    allowedEmails: ['owner@example.com'],
  });
  assert.deepEqual(routes.sort(), [
    '/',
    '/auth/callback',
    '/auth/login',
    '/auth/logout',
    '/auth/status',
  ]);
});

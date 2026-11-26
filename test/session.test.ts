import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import { BrowserSessions, loadSigningKey, sessionCookieName } from '../src/session.ts';
import { fakeCredentials } from './helpers.ts';

const DAY = 86_400_000;
const HOST = 'dsh.example';

async function make(
  options: { now?: () => number; allowed?: string[]; publicUrl?: string; days?: number } = {},
) {
  const credentials = fakeCredentials();
  const key = await loadSigningKey(credentials);
  const sessions = new BrowserSessions(key, {
    publicUrl: options.publicUrl ?? `https://${HOST}`,
    sessionDays: options.days ?? 30,
    allowedEmails: new Set(options.allowed ?? ['owner@example.com']),
    now: options.now,
  });
  return { sessions, key, credentials };
}

const pairOf = (setCookie: string) => setCookie.split(';')[0] ?? '';
const req = (cookie: string, host = HOST) => ({ headers: { host, cookie } });

test('issue and verify round-trip, with Lax/HttpOnly/Secure attributes', async () => {
  const { sessions } = await make();
  const setCookie = sessions.issue('Owner@Example.com');
  assert.match(setCookie, /^dsh-oidc-[A-Za-z0-9_-]+=v1\./u);
  assert.match(setCookie, /; Path=\/; HttpOnly; SameSite=Lax; Secure; Expires=/u);
  assert.match(setCookie, new RegExp(`Max-Age=${30 * 86_400};`, 'u'));
  assert.equal(sessions.verify(req(pairOf(setCookie))), 'owner@example.com');
  assert.equal(sessions.cookieName, sessionCookieName(HOST));
});

test('verify accepts Fetch Headers and other cookies around ours', async () => {
  const { sessions } = await make();
  const pair = pairOf(sessions.issue('owner@example.com'));
  const headers = new Headers({ host: HOST, cookie: `a=1; ${pair}; b=2` });
  assert.equal(sessions.verify({ headers }), 'owner@example.com');
});

test('no Secure attribute on an http public URL', async () => {
  const { sessions } = await make({ publicUrl: 'http://dsh.lan:3080' });
  assert.doesNotMatch(sessions.issue('owner@example.com'), /Secure/u);
  assert.equal(
    sessions.verify(req(pairOf(sessions.issue('owner@example.com')), 'dsh.lan:3080')),
    'owner@example.com',
  );
});

test('tampered payload or signature, and duplicates, are refused', async () => {
  const { sessions } = await make();
  const pair = pairOf(sessions.issue('owner@example.com'));
  const [name, value] = pair.split('=') as [string, string];
  const [v, body, sig] = value.split('.') as [string, string, string];
  const forgedBody = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(body, 'base64url').toString()), email: 'x@y' }),
  ).toString('base64url');
  assert.equal(sessions.verify(req(`${name}=${v}.${forgedBody}.${sig}`)), undefined);
  assert.equal(sessions.verify(req(`${name}=${v}.${body}.${sig.slice(0, -2)}AA`)), undefined);
  assert.equal(sessions.verify(req(`${name}=${v}.${body}`)), undefined);
  assert.equal(sessions.verify(req(`${pair}; ${pair}`)), undefined);
  assert.equal(sessions.verify(req('')), undefined);
});

test('a cookie signed by another key is refused', async () => {
  const a = await make();
  const b = await make();
  assert.equal(b.sessions.verify(req(pairOf(a.sessions.issue('owner@example.com')))), undefined);
});

test('wrong Host is refused (sessions are bound to the public authority)', async () => {
  const { sessions } = await make();
  const pair = pairOf(sessions.issue('owner@example.com'));
  assert.equal(sessions.verify(req(pair, 'DSH.example')), 'owner@example.com');
  assert.equal(sessions.verify(req(pair, '10.0.0.5:3080')), undefined);
});

test('expiry, future issue time and over-long lifetimes are refused', async () => {
  let now = 1_000_000_000_000;
  const { sessions, key } = await make({ now: () => now, days: 1 });
  const pair = pairOf(sessions.issue('owner@example.com'));
  now += DAY - 1;
  assert.equal(sessions.verify(req(pair)), 'owner@example.com');
  now += 1;
  assert.equal(sessions.verify(req(pair)), undefined);
  // A correctly signed payload that claims more than the configured lifetime.
  const forge = (payload: object) => {
    const body = `v1.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    return `${sessions.cookieName}=${body}.${createHmac('sha256', key).update(body).digest('base64url')}`;
  };
  const base = { authority: HOST, email: 'owner@example.com' };
  assert.equal(sessions.verify(req(forge({ ...base, iat: now, exp: now + 2 * DAY }))), undefined);
  assert.equal(sessions.verify(req(forge({ ...base, iat: now + 10, exp: now + 100 }))), undefined);
  assert.equal(sessions.verify(req(forge({ ...base, iat: now, exp: now + 100 }))), base.email);
});

test('removing an e-mail from the allow-list revokes its sessions', async () => {
  const allowed = new Set(['owner@example.com']);
  const credentials = fakeCredentials();
  const sessions = new BrowserSessions(await loadSigningKey(credentials), {
    publicUrl: `https://${HOST}`,
    sessionDays: 30,
    allowedEmails: allowed,
  });
  const pair = pairOf(sessions.issue('owner@example.com'));
  assert.equal(sessions.verify(req(pair)), 'owner@example.com');
  allowed.delete('owner@example.com');
  assert.equal(sessions.verify(req(pair)), undefined);
});

test('the signing key is created once, reused after a restart, and a corrupt record fails', async () => {
  const credentials = fakeCredentials();
  const first = await loadSigningKey(credentials);
  const second = await loadSigningKey(credentials);
  assert.equal(first.byteLength, 32);
  assert.deepEqual(first, second);
  assert.equal(credentials.records.get('oidc-login/browser-session')?.kind, 'grant');
  await assert.rejects(
    loadSigningKey(fakeCredentials({ kind: 'secret', payload: 'x' })),
    /unsupported format/u,
  );
  await assert.rejects(
    loadSigningKey(fakeCredentials({ kind: 'grant', payload: { version: 1, secret: 'abc' } })),
    /invalid signing key/u,
  );
});

test('clear() expires the cookie', async () => {
  const { sessions } = await make();
  assert.match(sessions.clear(), new RegExp(`^${sessions.cookieName}=; Max-Age=0; Path=/`, 'u'));
});

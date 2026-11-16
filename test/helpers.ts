import { generateKeyPairSync, type KeyObject, sign } from 'node:crypto';
import { createServer, type IncomingMessage, request, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ResolvedConfig } from '../src/config.ts';
import type { ConnectionService, Logger, RequestLike, ResponseSink } from '../src/context.ts';

export const LAUNCH_TOKEN = 'launch-token-abc';

/** A fake of dsh's connection service with the same index semantics as BrowserAuth. */
export function fakeConnection(): ConnectionService & { minted: string[] } {
  const minted: string[] = [];
  return {
    minted,
    browserPeer: { kind: 'owner' },
    authenticatedUrl(base: string) {
      const url = new URL(base);
      url.searchParams.set('token', LAUNCH_TOKEN);
      return url.href;
    },
    authorizeIndex(req: RequestLike, res: ResponseSink) {
      const url = new URL(req.url ?? '/', 'http://x');
      const host = req.headers.host as string | undefined;
      if (url.searchParams.has('token')) {
        if (url.pathname === '/' && url.searchParams.get('token') === LAUNCH_TOKEN && host) {
          const value = `cookie-for-${host}`;
          minted.push(value);
          res.writeHead(303, {
            location: './',
            'set-cookie': `dsh-auth-x=${value}; Path=/; HttpOnly; SameSite=Lax`,
          });
          res.end();
          return false;
        }
        res.writeHead(401, { 'content-type': 'text/plain' });
        res.end('dsh web authentication required\n');
        return false;
      }
      const cookie = (req.headers.cookie as string | undefined) ?? '';
      if (host && cookie.includes(`dsh-auth-x=cookie-for-${host}`)) return true;
      res.writeHead(401, { 'content-type': 'text/plain' });
      res.end('dsh web authentication required\n');
      return false;
    },
  };
}

export const silentLogger = (): Logger & { lines: string[] } => {
  const lines: string[] = [];
  const push = (...args: unknown[]) => {
    lines.push(args.map(String).join(' '));
  };
  return { lines, info: push, warn: push, error: push };
};

export function config(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    issuer: 'https://auth.example',
    clientId: 'dsh',
    clientSecret: 'client-secret',
    publicUrl: 'https://dsh.example',
    allowedEmails: new Set(['owner@example.com']),
    redirectRoot: true,
    scopes: ['openid', 'email', 'profile'],
    ...overrides,
  };
}

/** A minimal OpenID Provider (discovery, authorize, token, userinfo, jwks) on 127.0.0.1. */
export class MockProvider {
  readonly keys: { privateKey: KeyObject; publicKey: KeyObject } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  issuer = '';
  email = 'owner@example.com';
  emailVerified: boolean | undefined = true;
  /** Mutators applied to the ID token claims, for negative tests. */
  tamper: (claims: Record<string, unknown>) => void = () => {};
  signWith: KeyObject | undefined;
  readonly codes = new Map<string, { nonce: string; challenge: string; redirectUri: string }>();
  tokenRequests: URLSearchParams[] = [];
  private server = createServer((req, res) => {
    this.handle(req, res).catch((error) => {
      res.writeHead(500).end(String(error));
    });
  });

  async start(): Promise<this> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this;
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  idToken(claims: Record<string, unknown>): string {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'JWT' })).toString(
      'base64url',
    );
    const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
    const signature = sign(
      'sha256',
      Buffer.from(`${header}.${payload}`),
      this.signWith ?? this.keys.privateKey,
    );
    return `${header}.${payload}.${signature.toString('base64url')}`;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', this.issuer);
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    };
    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        return json(200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/authorize`,
          token_endpoint: `${this.issuer}/token`,
          userinfo_endpoint: `${this.issuer}/userinfo`,
          jwks_uri: `${this.issuer}/jwks`,
          end_session_endpoint: `${this.issuer}/logout`,
        });
      case '/jwks':
        return json(200, {
          keys: [
            {
              ...this.keys.publicKey.export({ format: 'jwk' }),
              kid: 'k1',
              use: 'sig',
              alg: 'RS256',
            },
          ],
        });
      case '/token': {
        let body = '';
        for await (const chunk of req) body += chunk;
        const form = new URLSearchParams(body);
        this.tokenRequests.push(form);
        const auth = Buffer.from(
          (req.headers.authorization ?? '').replace(/^Basic /u, ''),
          'base64',
        ).toString();
        if (auth !== 'dsh:client-secret') return json(401, { error: 'invalid_client' });
        const grant = this.codes.get(form.get('code') ?? '');
        if (grant === undefined || grant.redirectUri !== form.get('redirect_uri')) {
          return json(400, { error: 'invalid_grant' });
        }
        this.codes.delete(form.get('code') ?? '');
        const { createHash } = await import('node:crypto');
        const challenge = createHash('sha256')
          .update(form.get('code_verifier') ?? '')
          .digest('base64url');
        if (challenge !== grant.challenge)
          return json(400, { error: 'invalid_grant', error_description: 'pkce' });
        const now = Math.floor(Date.now() / 1000);
        const claims: Record<string, unknown> = {
          iss: this.issuer,
          sub: 'user-1',
          aud: ['dsh'],
          exp: now + 300,
          iat: now,
          nonce: grant.nonce,
        };
        this.tamper(claims);
        return json(200, {
          access_token: 'access-1',
          token_type: 'bearer',
          id_token: this.idToken(claims),
        });
      }
      case '/userinfo':
        if (req.headers.authorization !== 'Bearer access-1')
          return json(401, { error: 'invalid_token' });
        return json(200, {
          sub: 'user-1',
          email: this.email,
          ...(this.emailVerified === undefined ? {} : { email_verified: this.emailVerified }),
          name: 'Owner',
        });
      default:
        res.writeHead(404).end();
    }
  }

  /** Simulate the user approving the login at the authorize URL; returns the callback URL. */
  approve(authorizeUrl: string): string {
    const url = new URL(authorizeUrl);
    const code = `code-${this.codes.size}-${Math.random()}`;
    this.codes.set(code, {
      nonce: url.searchParams.get('nonce') ?? '',
      challenge: url.searchParams.get('code_challenge') ?? '',
      redirectUri: url.searchParams.get('redirect_uri') ?? '',
    });
    const back = new URL(url.searchParams.get('redirect_uri') ?? '');
    back.searchParams.set('code', code);
    back.searchParams.set('state', url.searchParams.get('state') ?? '');
    return back.href;
  }
}

/** Run a route handler against a real node:http server; returns status, headers and body. */
export async function call(
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
  input: { path: string; method?: string; headers?: Record<string, string> },
): Promise<{
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}> {
  const server = createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((error) => {
      res.writeHead(500).end(String(error));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  try {
    return await new Promise((resolve, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: input.path,
          method: input.method ?? 'GET',
          headers: input.headers,
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
          });
          res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
        },
      );
      req.on('error', reject);
      req.end();
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

export function setCookies(headers: Record<string, string | string[] | undefined>): string[] {
  const value = headers['set-cookie'];
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

/** The `name=value` of a Set-Cookie header, for sending it back. */
export function cookiePair(setCookie: string): string {
  return setCookie.split(';')[0] ?? '';
}

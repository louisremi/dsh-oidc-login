import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ResolvedConfig } from './config.ts';
import type { Logger } from './context.ts';
import { type OidcClient, randomToken } from './oidc.ts';
import type { BrowserSessions } from './session.ts';

export const LOGIN_PATH = '/auth/login';
export const CALLBACK_PATH = '/auth/callback';
export const LOGOUT_PATH = '/auth/logout';
const STATE_COOKIE = 'dsh-oidc-state';
const STATE_TTL_MS = 10 * 60 * 1000;
const MAX_PENDING = 64;

interface Pending {
  nonce: string;
  codeVerifier: string;
  createdAt: number;
}

export interface RouteDeps {
  config: ResolvedConfig;
  oidc: Pick<OidcClient, 'authorizationUrl' | 'completeLogin' | 'discover'>;
  sessions: Pick<BrowserSessions, 'issue' | 'clear'>;
  logger: Logger;
  now?: () => number;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/gu, (c) => `&#${c.charCodeAt(0)};`);
}

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'content-security-policy':
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
};

function page(res: ServerResponse, status: number, title: string, body: string): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'text/html; charset=utf-8' });
  res.end(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>` +
      '<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;line-height:1.5;color:#222}a{color:#2563eb}</style>' +
      `</head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`,
  );
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function readCookie(req: IncomingMessage, name: string): string | undefined {
  const raw = header(req, 'cookie');
  if (raw === undefined) return undefined;
  for (const part of raw.split(';')) {
    const at = part.indexOf('=');
    if (at !== -1 && part.slice(0, at).trim() === name) return part.slice(at + 1).trim();
  }
  return undefined;
}

function sameToken(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

const digest = (text: string) => createHash('sha256').update(text).digest('base64url');

/**
 * Cookies dsh's own sign-in methods set on an HTTP listener (the usual case
 * behind a TLS proxy): the launch-token cookie `dsh-auth-<sha256(host)>` and
 * the QR/pairing cookie `dsh-remote-<sha256(http://host)>`.
 */
export function dshCookieNames(host: string): string[] {
  try {
    return [`dsh-auth-${digest(host)}`, `dsh-remote-${digest(new URL(`http://${host}`).origin)}`];
  } catch {
    return [`dsh-auth-${digest(host)}`];
  }
}

export class LoginRoutes {
  private readonly pending = new Map<string, Pending>();
  private readonly publicHost: string;
  private readonly secure: boolean;
  private readonly redirectUri: string;
  private readonly now: () => number;

  private readonly deps: RouteDeps;

  constructor(deps: RouteDeps) {
    this.deps = deps;
    const url = new URL(deps.config.publicUrl);
    this.publicHost = url.host;
    this.secure = url.protocol === 'https:';
    this.redirectUri = `${deps.config.publicUrl}${CALLBACK_PATH}`;
    this.now = deps.now ?? Date.now;
  }

  /** Requests must arrive under the configured public authority: the cookie dsh mints is bound to it. */
  private hostMatches(req: IncomingMessage): boolean {
    return (header(req, 'host') ?? '').toLowerCase() === this.publicHost.toLowerCase();
  }

  private stateCookie(value: string, maxAgeSeconds: number): string {
    return `${STATE_COOKIE}=${value}; Max-Age=${maxAgeSeconds}; Path=/auth; HttpOnly; SameSite=Lax${this.secure ? '; Secure' : ''}`;
  }

  private prune(): void {
    const cutoff = this.now() - STATE_TTL_MS;
    for (const [state, entry] of this.pending)
      if (entry.createdAt < cutoff) this.pending.delete(state);
    while (this.pending.size >= MAX_PENDING) {
      const oldest = this.pending.keys().next().value;
      if (oldest === undefined) break;
      this.pending.delete(oldest);
    }
  }

  private wrongHost(res: ServerResponse): void {
    page(
      res,
      403,
      'Wrong address',
      `<p>Sign-in is only available at <a href="${escapeHtml(this.deps.config.publicUrl)}${LOGIN_PATH}">${escapeHtml(this.deps.config.publicUrl)}</a>.</p>`,
    );
  }

  /** GET /auth/login: start the authorization-code flow. */
  login = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' }).end();
      return;
    }
    if (!this.hostMatches(req)) return this.wrongHost(res);
    this.prune();
    const state = randomToken();
    const entry: Pending = {
      nonce: randomToken(),
      codeVerifier: randomToken(48),
      createdAt: this.now(),
    };
    let location: string;
    try {
      location = await this.deps.oidc.authorizationUrl({
        redirectUri: this.redirectUri,
        scopes: this.deps.config.scopes,
        state,
        nonce: entry.nonce,
        codeVerifier: entry.codeVerifier,
      });
    } catch (error) {
      this.deps.logger.warn('oidc-login: identity provider unavailable', error);
      return page(
        res,
        503,
        'Sign-in unavailable',
        '<p>The identity provider cannot be reached right now. Try again later, or <a href="/">sign in to dsh another way</a> (launch token or device pairing).</p>',
      );
    }
    this.pending.set(state, entry);
    res.writeHead(302, {
      ...SECURITY_HEADERS,
      location,
      'set-cookie': this.stateCookie(state, STATE_TTL_MS / 1000),
    });
    res.end();
  };

  private denied(res: ServerResponse, reason: string, detail?: unknown): void {
    this.deps.logger.warn(
      `oidc-login: login refused: ${reason}`,
      ...(detail === undefined ? [] : [detail]),
    );
    res.writeHead(403, {
      ...SECURITY_HEADERS,
      'content-type': 'text/html; charset=utf-8',
      'set-cookie': this.stateCookie('', 0),
    });
    res.end(
      `<!doctype html><meta charset="utf-8"><title>Sign-in refused</title><p>Sign-in refused. <a href="${LOGIN_PATH}">Try again</a>, or <a href="/">sign in to dsh another way</a>.</p>`,
    );
  }

  /** GET /auth/callback: finish the flow and hand the browser dsh's own session cookie. */
  callback = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== 'GET') {
      res.writeHead(405, { allow: 'GET' }).end();
      return;
    }
    if (!this.hostMatches(req)) return this.wrongHost(res);
    const url = new URL(req.url ?? '/', 'http://callback.invalid');
    const state = url.searchParams.get('state') ?? '';
    const cookieState = readCookie(req, STATE_COOKIE) ?? '';
    // The state must match this browser's cookie (login CSRF) and a pending login (replay).
    const entry = state === '' ? undefined : this.pending.get(state);
    if (entry === undefined || cookieState === '' || !sameToken(state, cookieState)) {
      return this.denied(res, 'unknown or mismatched state');
    }
    this.pending.delete(state);
    if (this.now() - entry.createdAt > STATE_TTL_MS) return this.denied(res, 'login took too long');
    const error = url.searchParams.get('error');
    if (error !== null) return this.denied(res, `provider returned error=${error}`);
    const code = url.searchParams.get('code');
    if (code === null || code === '') return this.denied(res, 'no authorization code');

    let identity: Awaited<ReturnType<OidcClient['completeLogin']>>;
    try {
      identity = await this.deps.oidc.completeLogin({
        code,
        redirectUri: this.redirectUri,
        codeVerifier: entry.codeVerifier,
        nonce: entry.nonce,
      });
    } catch (cause) {
      return this.denied(res, 'token exchange or verification failed', cause);
    }
    const email = identity.email.toLowerCase();
    if (!this.deps.config.allowedEmails.has(email)) {
      return this.denied(res, `${identity.email} is not in DSH_OIDC_ALLOWED_EMAILS`);
    }
    if (identity.emailVerified === false && this.deps.config.requireVerifiedEmail) {
      return this.denied(
        res,
        `${identity.email} is not verified by the provider (set DSH_OIDC_REQUIRE_VERIFIED_EMAIL=0 to accept it)`,
      );
    }

    this.deps.logger.info(`oidc-login: ${identity.email} signed in`);
    res.writeHead(303, {
      ...SECURITY_HEADERS,
      location: '/',
      'set-cookie': [this.stateCookie('', 0), this.deps.sessions.issue(email)],
    });
    res.end();
  };

  /**
   * GET /auth/logout: drop this plugin's session in this browser, and dsh's
   * own token and QR/pairing cookies, then end the provider session if it can.
   */
  logout = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const host = header(req, 'host') ?? '';
    let location = '/auth/login';
    try {
      const meta = await this.deps.oidc.discover();
      if (meta.end_session_endpoint !== undefined) {
        const end = new URL(meta.end_session_endpoint);
        end.searchParams.set('client_id', this.deps.config.clientId);
        end.searchParams.set(
          'post_logout_redirect_uri',
          `${this.deps.config.publicUrl}${LOGIN_PATH}`,
        );
        location = end.href;
      }
    } catch {
      // Provider down: still clear the local cookie.
    }
    res.writeHead(303, {
      ...SECURITY_HEADERS,
      location,
      'set-cookie': [
        this.deps.sessions.clear(),
        ...(host === ''
          ? []
          : dshCookieNames(host).map(
              (name) =>
                `${name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${this.secure ? '; Secure' : ''}`,
            )),
      ],
    });
    res.end();
  };
}

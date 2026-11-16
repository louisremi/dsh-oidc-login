import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ResolvedConfig } from './config.ts';
import type { ConnectionService, Logger, RequestLike, WebServerService } from './context.ts';
import { type OidcClient, randomToken } from './oidc.ts';

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
  connection: ConnectionService;
  webServer: Pick<WebServerService, 'readResource'>;
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

function header(req: RequestLike, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function readCookie(req: RequestLike, name: string): string | undefined {
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

/** dsh's browser-session cookie name for an HTTP listener: `dsh-auth-` + base64url(sha256(host)). */
export function dshCookieName(host: string): string {
  return `dsh-auth-${createHash('sha256').update(host).digest('base64url')}`;
}

/** Whether a request is a top-level browser navigation that expects an HTML page. */
export function isHtmlNavigation(req: RequestLike): boolean {
  if (req.method !== 'GET') return false;
  const mode = header(req, 'sec-fetch-mode');
  if (mode !== undefined) return mode === 'navigate';
  return (header(req, 'accept') ?? '').includes('text/html');
}

/** Captures what dsh's authorizeIndex writes, so the caller can decide what to send. */
class CapturedResponse {
  status = 200;
  headers: Record<string, string | string[]> = {};
  body: string | undefined;
  writeHead(status: number, headers?: Record<string, string | string[]>): this {
    this.status = status;
    this.headers = headers ?? {};
    return this;
  }
  end(body?: string): this {
    this.body = body;
    return this;
  }
  replay(res: ServerResponse): void {
    res.writeHead(this.status, this.headers);
    res.end(this.body);
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
  private hostMatches(req: RequestLike): boolean {
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
        '<p>The identity provider cannot be reached right now. Try again later, or open the login link printed in the container logs (<code>dsh web: …?token=…</code>).</p>',
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
      `<!doctype html><meta charset="utf-8"><title>Sign-in refused</title><p>Sign-in refused. <a href="${LOGIN_PATH}">Try again</a>.</p>`,
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
    if (identity.emailVerified === false)
      return this.denied(res, `${identity.email} is not verified`);

    // Mint dsh's own session cookie by replaying its launch-token exchange in-process.
    // The token never leaves this process; dsh signs the cookie for the request's Host.
    const token = new URL(
      this.deps.connection.authenticatedUrl('http://dsh.invalid/'),
    ).searchParams.get('token');
    if (token === null) return this.denied(res, 'dsh did not expose a launch token');
    const minted = new CapturedResponse();
    this.deps.connection.authorizeIndex(
      {
        method: 'GET',
        url: `/?token=${encodeURIComponent(token)}`,
        headers: { host: header(req, 'host') },
      },
      minted,
    );
    const sessionCookie = minted.headers['set-cookie'];
    if (minted.status !== 303 || sessionCookie === undefined) {
      return this.denied(res, `dsh refused the launch token (status ${minted.status})`);
    }
    this.deps.logger.info(`oidc-login: ${identity.email} signed in`);
    res.writeHead(303, {
      ...SECURITY_HEADERS,
      location: '/',
      'set-cookie': [
        this.stateCookie('', 0),
        ...(Array.isArray(sessionCookie) ? sessionCookie : [sessionCookie]),
      ],
    });
    res.end();
  };

  /** GET /auth/logout: drop dsh's cookie in this browser, then end the provider session if it can. */
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
      'set-cookie': `${dshCookieName(host)}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${this.secure ? '; Secure' : ''}`,
    });
    res.end();
  };

  /**
   * GET / : dsh's own index handling, except that a browser navigation that
   * would get dsh's bare 401 is sent to the sign-in page instead. Token links,
   * valid cookies, API clients and health checks behave exactly as without
   * this plugin.
   */
  root = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' }).end();
      return;
    }
    const captured = new CapturedResponse();
    const authorized = this.deps.connection.authorizeIndex(req, captured);
    if (!authorized) {
      const url = new URL(req.url ?? '/', 'http://root.invalid');
      if (
        captured.status === 401 &&
        !url.searchParams.has('token') &&
        isHtmlNavigation(req) &&
        this.hostMatches(req)
      ) {
        res.writeHead(302, { ...SECURITY_HEADERS, location: LOGIN_PATH });
        res.end();
        return;
      }
      captured.replay(res);
      return;
    }
    // Authenticated: serve the index exactly as dsh's fallback would. "/" is now
    // our handler route, so read the same document through its other name.
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      for (const item of typeof value === 'string' ? [value] : (value ?? []))
        headers.append(name, item);
    }
    const response = await this.deps.webServer.readResource(
      new Request('http://dsh.invalid/index.html', {
        method: req.method === 'HEAD' ? 'HEAD' : 'GET',
        headers,
      }),
      this.deps.connection.browserPeer,
    );
    const out: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      out[name] = value;
    });
    res.writeHead(response.status, out);
    if (req.method === 'HEAD' || response.body === null) {
      res.end();
      return;
    }
    res.end(Buffer.from(await response.arrayBuffer()));
  };
}

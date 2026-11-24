/**
 * The two things this plugin needs from dsh's browser authentication, behind
 * one interface, for both dsh generations:
 *
 * - up to 0.2.2, `connection.authorizeIndex` / `connection.authenticatedUrl`;
 * - since 0.2.3-alpha.1, the Token Provider plugin
 *   (`@deepseek-ai/dsh-host-authentication-token`), reached through public
 *   events only: it adds the signed login URL to `webserver/entry-url` and
 *   exchanges `/?token=` in the `webserver/request` middleware, while
 *   `webServer.authorize` makes the cookie decision for routes. See dsh's
 *   upgrade guide v0.2.2-rc.2/connection-page-peer.
 */
import type {
  AdmissionRequest,
  LegacyConnectionService,
  PluginContext,
  RequestLike,
  ResponseSink,
} from './context.ts';

/** A captured HTTP reply: what dsh wrote, so the caller decides what to send. */
export interface Captured {
  status: number;
  headers: Record<string, string | string[]>;
  body: string | undefined;
}

export interface DshAuth {
  /**
   * Run dsh's launch-token exchange for `host` in-process. The token never
   * leaves this process; dsh signs the cookie for that authority.
   * Resolves to dsh's reply: 303 with `set-cookie` on success.
   */
  mintSessionCookie(host: string | undefined): Promise<Captured>;
  /**
   * dsh's own answer for `GET /`: `authorized` when the request carries a
   * valid session, otherwise the reply dsh would send (token exchange 303,
   * or 401).
   */
  authorizeIndex(req: RequestLike): Promise<{ authorized: boolean; reply: Captured }>;
  /** The Peer the index is rendered for. */
  readonly browserPeer: unknown;
}

/** Records what a handler writes. */
export class CapturedResponse implements ResponseSink, Captured {
  status = 200;
  headers: Record<string, string | string[]> = {};
  body: string | undefined;
  writeHead(status: number, headers?: Record<string, string | string[]>): this {
    this.status = status;
    this.headers = headers ?? {};
    return this;
  }
  setHeader(name: string, value: string | string[]): this {
    this.headers[name.toLowerCase()] = value;
    return this;
  }
  end(body?: string): this {
    this.body = body;
    return this;
  }
}

const PLACEHOLDER_BASE = 'http://dsh.invalid/';

function launchToken(url: string | undefined): string | null {
  return url === undefined ? null : new URL(url).searchParams.get('token');
}

function legacyAuth(connection: LegacyConnectionService): DshAuth {
  return {
    browserPeer: connection.browserPeer,
    async mintSessionCookie(host) {
      const minted = new CapturedResponse();
      const token = launchToken(connection.authenticatedUrl(PLACEHOLDER_BASE));
      if (token === null) return minted.writeHead(500);
      connection.authorizeIndex(
        { method: 'GET', url: `/?token=${encodeURIComponent(token)}`, headers: { host } },
        minted,
      );
      return minted;
    },
    async authorizeIndex(req) {
      const reply = new CapturedResponse();
      return { authorized: connection.authorizeIndex(req, reply), reply };
    },
  };
}

function tokenProviderAuth(ctx: PluginContext): DshAuth {
  const webServer = ctx.webServer;
  const authorize = webServer.authorize!.bind(webServer);
  /** The signed login URL the Token Provider announces, or undefined without one. */
  const entryUrl = (): string | undefined => {
    const entries: { url: string }[] = [];
    ctx.emit(webServer, 'webserver/entry-url', PLACEHOLDER_BASE, entries);
    return entries.find((entry) => launchToken(entry.url) !== null)?.url;
  };
  /** Run dsh's request middleware for one synthetic request; a fall-through is a 404. */
  const exchange = async (req: RequestLike): Promise<Captured> => {
    const reply = new CapturedResponse();
    let fellThrough = false;
    await ctx.waterfall(webServer, 'webserver/request', req, reply, () => {
      fellThrough = true;
    });
    return fellThrough ? reply.writeHead(404) : reply;
  };
  return {
    browserPeer: ctx.connection.browserPeer,
    async mintSessionCookie(host) {
      const token = launchToken(entryUrl());
      if (token === null) return new CapturedResponse().writeHead(500);
      return exchange({
        method: 'GET',
        url: `/?token=${encodeURIComponent(token)}`,
        headers: { host },
      });
    },
    async authorizeIndex(req) {
      const url = new URL(req.url ?? '/', PLACEHOLDER_BASE);
      // Token links are dsh's own exchange: answer exactly as dsh would.
      if (url.searchParams.has('token')) return { authorized: false, reply: await exchange(req) };
      const request: AdmissionRequest = {
        headers: req.headers,
        method: req.method,
        url,
        transport: 'http',
        socket: req.socket,
      };
      const admission = authorize(request, 'required');
      if (admission.kind === 'allow') return { authorized: true, reply: new CapturedResponse() };
      const reply = new CapturedResponse().writeHead(admission.status, {
        'cache-control': 'no-store',
      });
      reply.end(admission.status === 401 ? 'unauthorized' : 'forbidden');
      return { authorized: false, reply };
    },
  };
}

/**
 * Pick the adapter for the running dsh, or undefined when neither API is
 * there (the caller then stays disabled; the token link keeps working).
 */
export function resolveDshAuth(ctx: PluginContext): DshAuth | undefined {
  const { connection, webServer } = ctx;
  if (typeof webServer.readResource !== 'function') return undefined;
  if (
    typeof connection.authorizeIndex === 'function' &&
    typeof connection.authenticatedUrl === 'function'
  ) {
    return legacyAuth(connection as LegacyConnectionService);
  }
  if (
    typeof webServer.authorize === 'function' &&
    typeof ctx.emit === 'function' &&
    typeof ctx.waterfall === 'function'
  ) {
    return tokenProviderAuth(ctx);
  }
  return undefined;
}

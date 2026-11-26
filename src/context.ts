/**
 * Structural types for the Harness services this plugin consumes. The plugin
 * has zero runtime dependencies, so these interfaces describe only the
 * members it calls; the `inject` list in src/index.ts guarantees they exist.
 * src/dsh-auth.ts adapts the two dsh generations behind one interface.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

/** The minimal response surface dsh's index authorisation writes to. */
export interface ResponseSink {
  writeHead(status: number, headers?: Record<string, string | string[]>): unknown;
  end(body?: string): unknown;
}

/** The request surface dsh's index authorisation reads. */
export interface RequestLike {
  method?: string | undefined;
  url?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  socket?: unknown;
}

/**
 * dsh up to 0.2.2: the connection service owns browser authentication.
 * Removed in 0.2.3-alpha.1 (upgrade guide v0.2.2-rc.2/connection-page-peer).
 */
export interface LegacyConnectionService {
  /** dsh's own index authorisation: token exchange (303 + Set-Cookie), cookie check, or 401. */
  authorizeIndex(request: RequestLike, response: ResponseSink): boolean;
  /** The clean URL with this process's launch token added. */
  authenticatedUrl(baseUrl: string): string;
  /** The Peer every cookie-authenticated browser shares. */
  browserPeer: unknown;
}

/** dsh 0.2.3+: the connection service only keeps the trusted in-process Peer. */
export interface ConnectionService {
  browserPeer: unknown;
  authorizeIndex?: LegacyConnectionService['authorizeIndex'];
  authenticatedUrl?: LegacyConnectionService['authenticatedUrl'];
}

export type RouteHandler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

/** dsh 0.2.3+ route admission: what `webServer.authorize` decides for one request. */
export type Admission = { kind: 'allow'; peer?: unknown } | { kind: 'deny'; status: number };

/** What dsh 0.2.3+ `webServer.authorize` reads from a request. */
export interface AdmissionRequest {
  headers: Record<string, string | string[] | undefined>;
  method?: string | undefined;
  url: URL;
  transport: 'http';
  socket?: unknown;
}

export interface WebServerService {
  /** `auth` exists since dsh 0.2.3 (default `required`); older dsh ignores it. */
  register(route: {
    kind: 'exact' | 'prefix';
    path: string;
    handler: RouteHandler;
    auth?: 'anonymous' | 'required' | 'deny';
  }): () => void;
  readResource(request: Request, peer: unknown): Promise<Response>;
  /** dsh 0.2.3+: the admission decision WebServer applies to a route. */
  authorize?(request: AdmissionRequest, auth?: 'anonymous' | 'required' | 'deny'): Admission;
}

export interface Logger {
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

export interface PluginContext {
  connection: ConnectionService;
  webServer: WebServerService;
  logger?: Logger | undefined;
  effect(callback: () => void | (() => void | Promise<void>), label?: string): unknown;
  /** Cordis events: synchronous broadcast, and the `webserver/request` middleware chain. */
  emit(thisArg: unknown, name: string, ...args: unknown[]): void;
  waterfall(thisArg: unknown, name: string, ...args: unknown[]): unknown;
}

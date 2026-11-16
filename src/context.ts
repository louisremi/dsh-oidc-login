/**
 * Structural types for the Harness services this plugin consumes. The plugin
 * has zero runtime dependencies, so these interfaces describe only the
 * members it calls; the `inject` list in src/index.ts guarantees they exist.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

/** The minimal response surface dsh's `connection.authorizeIndex` writes to. */
export interface ResponseSink {
  writeHead(status: number, headers?: Record<string, string | string[]>): unknown;
  end(body?: string): unknown;
}

/** The request surface dsh's `connection.authorizeIndex` reads. */
export interface RequestLike {
  method?: string | undefined;
  url?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
}

export interface ConnectionService {
  /** dsh's own index authorisation: token exchange (303 + Set-Cookie), cookie check, or 401. */
  authorizeIndex(request: RequestLike, response: ResponseSink): boolean;
  /** The clean URL with this process's launch token added. */
  authenticatedUrl(baseUrl: string): string;
  /** The Peer every cookie-authenticated browser shares. */
  browserPeer: unknown;
}

export type RouteHandler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

export interface WebServerService {
  register(route: { kind: 'exact' | 'prefix'; path: string; handler: RouteHandler }): () => void;
  readResource(request: Request, peer: unknown): Promise<Response>;
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
}

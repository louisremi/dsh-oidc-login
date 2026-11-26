/**
 * Structural types for the dsh (0.2.3+) services this plugin consumes. The
 * plugin has zero runtime dependencies, so these interfaces describe only the
 * members it calls; the `inject` list in src/index.ts guarantees they exist.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

/** Request headers in either the Fetch or the node:http representation. */
export type HeadersLike =
  | Headers
  | Readonly<Record<string, string | readonly string[] | undefined>>;

export type RouteHandler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

export interface WebServerService {
  register(route: {
    kind: 'exact' | 'prefix';
    path: string;
    handler: RouteHandler;
    auth?: 'anonymous' | 'required' | 'deny';
  }): () => void;
}

/** The provider shape `connection.authentication.register` accepts. */
export interface AuthenticationProvider {
  /** Synchronously return a live Peer for this request, or undefined to let the next provider try. */
  authenticate(request: { headers: HeadersLike }): unknown;
}

export interface ConnectionService {
  createPeer(options: { principal: { kind: 'owner' } }): unknown;
  authentication: {
    register(provider: AuthenticationProvider): () => Promise<void>;
  };
}

export interface CredentialRecord {
  kind: string;
  payload: unknown;
}

export interface CredentialStore {
  modifyRecord(
    key: string,
    mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>,
  ): Promise<CredentialRecord | undefined>;
}

export interface Logger {
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

export interface PluginContext {
  connection: ConnectionService;
  webServer: WebServerService;
  credentials: CredentialStore;
  logger?: Logger | undefined;
  effect(callback: () => void | (() => void | Promise<void>), label?: string): unknown;
}

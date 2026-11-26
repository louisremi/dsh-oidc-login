/**
 * This plugin's own browser session: a signed cookie that dsh accepts through
 * a registered `AuthenticationProvider` (dsh 0.2.3+, `connection.authentication`),
 * the same seam dsh's built-in remote login uses. The launch token is never
 * read, and no other provider's cookie is minted or replayed.
 *
 * Cookie: `dsh-oidc-<b64url sha256(authority)>=v1.<b64url payload>.<b64url HMAC-SHA256>`,
 * where the payload is `{ authority, email, iat, exp }` (milliseconds). The
 * signing key lives in dsh's credential store (`oidc-login/browser-session`):
 * deleting that record and restarting dsh revokes every session.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { CredentialRecord, CredentialStore, HeadersLike } from './context.ts';

export const CREDENTIAL_KEY = 'oidc-login/browser-session';
const VERSION = 1;
const SECRET_BYTES = 32;
const DAY_MS = 86_400_000;

interface Payload {
  authority: string;
  email: string;
  iat: number;
  exp: number;
}

function readSecret(record: CredentialRecord | undefined): Buffer | undefined {
  if (record === undefined) return undefined;
  const payload = record.payload as { version?: unknown; secret?: unknown } | null;
  if (
    record.kind !== 'grant' ||
    typeof payload !== 'object' ||
    payload === null ||
    payload.version !== VERSION ||
    typeof payload.secret !== 'string'
  ) {
    throw new Error(`credential ${CREDENTIAL_KEY} has an unsupported format`);
  }
  const secret = Buffer.from(payload.secret, 'base64url');
  if (secret.byteLength !== SECRET_BYTES) {
    throw new Error(`credential ${CREDENTIAL_KEY} holds an invalid signing key`);
  }
  return secret;
}

/** Load the signing key, creating it atomically on first start; an existing key is never replaced. */
export async function loadSigningKey(credentials: CredentialStore): Promise<Buffer> {
  const fresh: CredentialRecord = {
    kind: 'grant',
    payload: { version: VERSION, secret: randomBytes(SECRET_BYTES).toString('base64url') },
  };
  const stored = await credentials.modifyRecord(CREDENTIAL_KEY, async (current) => {
    if (current === undefined) return fresh;
    readSecret(current); // a corrupt record fails start-up instead of being overwritten
    return undefined;
  });
  const secret = readSecret(stored);
  if (secret === undefined) throw new Error(`credential ${CREDENTIAL_KEY} was not saved`);
  return secret;
}

function header(headers: HeadersLike, name: string): string | undefined {
  if (typeof (headers as Headers).get === 'function')
    return (headers as Headers).get(name) ?? undefined;
  const value = (headers as Record<string, string | readonly string[] | undefined>)[name];
  return typeof value === 'string' ? value : value?.[0];
}

/** The cookie name for an authority (`host[:port]`, lower case). */
export function sessionCookieName(authority: string): string {
  return `dsh-oidc-${createHash('sha256').update(authority).digest('base64url')}`;
}

export interface SessionOptions {
  /** dsh's external origin; sessions are bound to its authority. */
  publicUrl: string;
  /** Absolute session lifetime in whole days. */
  sessionDays: number;
  /** Checked on every request, so removing an e-mail revokes its sessions at once. */
  allowedEmails: ReadonlySet<string>;
  now?: () => number;
}

export class BrowserSessions {
  private readonly authority: string;
  private readonly secure: boolean;
  private readonly lifetimeMs: number;
  private readonly now: () => number;
  private readonly key: Buffer;
  private readonly options: SessionOptions;
  readonly cookieName: string;

  constructor(key: Buffer, options: SessionOptions) {
    this.key = key;
    this.options = options;
    const url = new URL(options.publicUrl);
    this.authority = url.host.toLowerCase();
    this.secure = url.protocol === 'https:';
    this.lifetimeMs = options.sessionDays * DAY_MS;
    this.now = options.now ?? Date.now;
    this.cookieName = sessionCookieName(this.authority);
  }

  private sign(body: string): Buffer {
    return createHmac('sha256', this.key).update(body).digest();
  }

  private attributes(maxAgeSeconds: number): string {
    return `Max-Age=${maxAgeSeconds}; Path=/; HttpOnly; SameSite=Lax${this.secure ? '; Secure' : ''}`;
  }

  /** Set-Cookie for a verified, allowed identity. */
  issue(email: string): string {
    const iat = this.now();
    const exp = iat + this.lifetimeMs;
    const payload: Payload = { authority: this.authority, email: email.toLowerCase(), iat, exp };
    const body = `v${VERSION}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
    const value = `${body}.${this.sign(body).toString('base64url')}`;
    return `${this.cookieName}=${value}; ${this.attributes(this.lifetimeMs / 1000)}; Expires=${new Date(exp).toUTCString()}`;
  }

  /** Set-Cookie that drops this browser's session. */
  clear(): string {
    return `${this.cookieName}=; ${this.attributes(0)}`;
  }

  /** The signed-in e-mail, or undefined. Never throws: dsh calls this on every request. */
  verify(request: { headers: HeadersLike }): string | undefined {
    try {
      if ((header(request.headers, 'host') ?? '').toLowerCase() !== this.authority)
        return undefined;
      const values = (header(request.headers, 'cookie') ?? '')
        .split(';')
        .map((part) => part.trim())
        .filter((part) => part.startsWith(`${this.cookieName}=`));
      if (values.length !== 1) return undefined;
      const parts = (values[0] ?? '').slice(this.cookieName.length + 1).split('.');
      const [version, encoded, signature] = parts;
      if (parts.length !== 3 || version !== `v${VERSION}` || !encoded || !signature)
        return undefined;
      const supplied = Buffer.from(signature, 'base64url');
      const expected = this.sign(`${version}.${encoded}`);
      if (supplied.byteLength !== expected.byteLength || !timingSafeEqual(supplied, expected)) {
        return undefined;
      }
      const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as Payload;
      const now = this.now();
      if (
        payload.authority !== this.authority ||
        typeof payload.email !== 'string' ||
        !Number.isSafeInteger(payload.iat) ||
        !Number.isSafeInteger(payload.exp) ||
        payload.iat > now ||
        payload.exp <= now ||
        payload.exp - payload.iat > this.lifetimeMs ||
        !this.options.allowedEmails.has(payload.email)
      ) {
        return undefined;
      }
      return payload.email;
    } catch {
      return undefined;
    }
  }
}

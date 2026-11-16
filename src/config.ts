import { readFileSync } from 'node:fs';

/** Plugin configuration as written in a cordis patch; every field falls back to an env var. */
export interface RawConfig {
  issuer?: string | undefined;
  clientId?: string | undefined;
  clientSecretFile?: string | undefined;
  publicUrl?: string | undefined;
  allowedEmails?: string[] | string | undefined;
  redirectRoot?: boolean | undefined;
  scopes?: string[] | undefined;
}

/** Fully resolved, validated configuration. */
export interface ResolvedConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** DSH's own external origin, without a trailing slash. */
  publicUrl: string;
  /** Lower-cased e-mail addresses allowed to log in. */
  allowedEmails: Set<string>;
  redirectRoot: boolean;
  scopes: string[];
}

export type ConfigResult =
  | { kind: 'disabled'; reason: string }
  | { kind: 'invalid'; reason: string }
  | { kind: 'enabled'; config: ResolvedConfig };

type Env = Record<string, string | undefined>;

function list(value: string[] | string | undefined): string[] {
  const items = Array.isArray(value) ? value : (value ?? '').split(/[\s,]+/u);
  return items.map((item) => item.trim()).filter((item) => item.length > 0);
}

function httpsOrigin(value: string, name: string, allowHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} is not a URL: ${JSON.stringify(value)}`);
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error(`${name} must use https: (got ${url.protocol})`);
  }
  if (url.search !== '' || url.hash !== '')
    throw new Error(`${name} must not carry a query or fragment`);
  return url.href.replace(/\/+$/u, '');
}

/**
 * Resolve the configuration from the patch values and the environment.
 * Reading the client secret deletes `DSH_OIDC_CLIENT_SECRET` from `env` so the
 * agent's tool subprocesses, which inherit dsh's environment, never see it.
 */
export function resolveConfig(raw: RawConfig | undefined, env: Env = process.env): ConfigResult {
  const issuerValue = raw?.issuer ?? env.DSH_OIDC_ISSUER ?? '';
  const inlineSecret = env.DSH_OIDC_CLIENT_SECRET;
  delete env.DSH_OIDC_CLIENT_SECRET;
  if (issuerValue.trim() === '') return { kind: 'disabled', reason: 'DSH_OIDC_ISSUER is not set' };
  try {
    // http: is only accepted for loopback test issuers.
    const loopback = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/u.test(issuerValue);
    const issuer = httpsOrigin(issuerValue.trim(), 'DSH_OIDC_ISSUER', loopback);
    const clientId = (raw?.clientId ?? env.DSH_OIDC_CLIENT_ID ?? '').trim();
    if (clientId === '') throw new Error('DSH_OIDC_CLIENT_ID is not set');
    const secretFile = (raw?.clientSecretFile ?? env.DSH_OIDC_CLIENT_SECRET_FILE ?? '').trim();
    const clientSecret =
      secretFile !== '' ? readFileSync(secretFile, 'utf8').trim() : (inlineSecret ?? '').trim();
    if (clientSecret === '') {
      throw new Error(
        'no client secret: set DSH_OIDC_CLIENT_SECRET_FILE (or DSH_OIDC_CLIENT_SECRET)',
      );
    }
    const publicValue = (raw?.publicUrl ?? env.DSH_OIDC_PUBLIC_URL ?? '').trim();
    if (publicValue === '') throw new Error('DSH_OIDC_PUBLIC_URL is not set');
    const publicUrl = httpsOrigin(publicValue, 'DSH_OIDC_PUBLIC_URL', true);
    if (new URL(publicUrl).pathname !== '/') {
      throw new Error('DSH_OIDC_PUBLIC_URL must be an origin (dsh is served at the root)');
    }
    const allowedEmails = new Set(
      list(raw?.allowedEmails ?? env.DSH_OIDC_ALLOWED_EMAILS).map((e) => e.toLowerCase()),
    );
    if (allowedEmails.size === 0) {
      throw new Error('DSH_OIDC_ALLOWED_EMAILS is empty; refusing to accept any OIDC login');
    }
    const redirectRoot = raw?.redirectRoot ?? env.DSH_OIDC_REDIRECT_ROOT !== '0';
    const scopes = raw?.scopes ?? ['openid', 'email', 'profile'];
    if (!scopes.includes('openid')) throw new Error('scopes must include openid');
    return {
      kind: 'enabled',
      config: { issuer, clientId, clientSecret, publicUrl, allowedEmails, redirectRoot, scopes },
    };
  } catch (error) {
    return { kind: 'invalid', reason: error instanceof Error ? error.message : String(error) };
  }
}

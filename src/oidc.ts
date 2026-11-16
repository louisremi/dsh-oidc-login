import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

/** The subset of OpenID Provider metadata this client uses. */
export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string | undefined;
}

/** What a successful login proves about the user. */
export interface VerifiedIdentity {
  sub: string;
  email: string;
  emailVerified: boolean | undefined;
  name: string | undefined;
}

/** A public JWK as published at jwks_uri. */
type Jwk = JsonWebKey & { kid?: string; use?: string; alg?: string };

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export class OidcError extends Error {
  override name = 'OidcError';
}

const CLOCK_SKEW_SECONDS = 120;

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function randomToken(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

export function pkceChallenge(verifier: string): string {
  return base64url(createHash('sha256').update(verifier).digest());
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== 'string' || value === '') throw new OidcError(`${what} is missing`);
  return value;
}

async function json(response: Response, what: string): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!response.ok)
    throw new OidcError(`${what} answered HTTP ${response.status}: ${text.slice(0, 300)}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new OidcError(`${what} did not return JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new OidcError(`${what} did not return a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

/** Signature algorithms accepted for ID tokens, mapped to node:crypto verify inputs. */
const ALGORITHMS: Record<string, { hash: string | null; options?: object }> = {
  RS256: { hash: 'sha256' },
  RS384: { hash: 'sha384' },
  RS512: { hash: 'sha512' },
  PS256: { hash: 'sha256', options: { padding: 6, saltLength: 32 } },
  PS384: { hash: 'sha384', options: { padding: 6, saltLength: 48 } },
  PS512: { hash: 'sha512', options: { padding: 6, saltLength: 64 } },
  ES256: { hash: 'sha256', options: { dsaEncoding: 'ieee-p1363' } },
  ES384: { hash: 'sha384', options: { dsaEncoding: 'ieee-p1363' } },
  ES512: { hash: 'sha512', options: { dsaEncoding: 'ieee-p1363' } },
  EdDSA: { hash: null },
};

/** A confidential OIDC client for the authorization-code flow with PKCE. */
export class OidcClient {
  private metadata: Promise<ProviderMetadata> | undefined;
  private jwks: Promise<Jwk[]> | undefined;

  private readonly issuer: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly fetchImpl: Fetch;

  constructor(issuer: string, clientId: string, clientSecret: string, fetchImpl: Fetch = fetch) {
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.fetchImpl = fetchImpl;
  }

  /** Provider metadata from discovery, cached; a failed lookup is retried on the next call. */
  discover(): Promise<ProviderMetadata> {
    this.metadata ??= this.loadMetadata().catch((error: unknown) => {
      this.metadata = undefined;
      throw error;
    });
    return this.metadata;
  }

  private async loadMetadata(): Promise<ProviderMetadata> {
    const response = await this.fetchImpl(`${this.issuer}/.well-known/openid-configuration`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    const doc = await json(response, 'discovery');
    // OIDC Discovery §4.3: the issuer in the document must equal the configured one.
    if (doc.issuer !== this.issuer && doc.issuer !== `${this.issuer}/`) {
      throw new OidcError(
        `discovery issuer ${JSON.stringify(doc.issuer)} does not match ${this.issuer}`,
      );
    }
    return {
      issuer: doc.issuer as string,
      authorization_endpoint: requireString(doc.authorization_endpoint, 'authorization_endpoint'),
      token_endpoint: requireString(doc.token_endpoint, 'token_endpoint'),
      userinfo_endpoint: requireString(doc.userinfo_endpoint, 'userinfo_endpoint'),
      jwks_uri: requireString(doc.jwks_uri, 'jwks_uri'),
      end_session_endpoint:
        typeof doc.end_session_endpoint === 'string' ? doc.end_session_endpoint : undefined,
    };
  }

  async authorizationUrl(input: {
    redirectUri: string;
    scopes: string[];
    state: string;
    nonce: string;
    codeVerifier: string;
  }): Promise<string> {
    const meta = await this.discover();
    const url = new URL(meta.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', input.redirectUri);
    url.searchParams.set('scope', input.scopes.join(' '));
    url.searchParams.set('state', input.state);
    url.searchParams.set('nonce', input.nonce);
    url.searchParams.set('code_challenge', pkceChallenge(input.codeVerifier));
    url.searchParams.set('code_challenge_method', 'S256');
    return url.href;
  }

  /** Exchange the code, verify the ID token, and read the user's e-mail from UserInfo. */
  async completeLogin(input: {
    code: string;
    redirectUri: string;
    codeVerifier: string;
    nonce: string;
  }): Promise<VerifiedIdentity> {
    const meta = await this.discover();
    const basic = Buffer.from(
      `${encodeURIComponent(this.clientId)}:${encodeURIComponent(this.clientSecret)}`,
    ).toString('base64');
    const tokenResponse = await this.fetchImpl(meta.token_endpoint, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Basic ${basic}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
      }).toString(),
      signal: AbortSignal.timeout(15_000),
    });
    const tokens = await json(tokenResponse, 'token endpoint');
    const accessToken = requireString(tokens.access_token, 'access_token');
    const idToken = requireString(tokens.id_token, 'id_token');
    if (typeof tokens.token_type !== 'string' || tokens.token_type.toLowerCase() !== 'bearer') {
      throw new OidcError('token_type is not Bearer');
    }
    const claims = await this.verifyIdToken(idToken, meta, input.nonce);
    const sub = requireString(claims.sub, 'id_token sub');

    const userinfoResponse = await this.fetchImpl(meta.userinfo_endpoint, {
      headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(10_000),
    });
    const userinfo = await json(userinfoResponse, 'userinfo endpoint');
    // OIDC Core §5.3.2: the UserInfo sub must match the ID token's.
    if (userinfo.sub !== sub) throw new OidcError('userinfo sub does not match the ID token');
    const email = userinfo.email ?? claims.email;
    if (typeof email !== 'string' || email === '') {
      throw new OidcError('the provider returned no e-mail (is the email scope granted?)');
    }
    const verified = userinfo.email_verified ?? claims.email_verified;
    const name = userinfo.name ?? claims.name;
    return {
      sub,
      email,
      emailVerified: typeof verified === 'boolean' ? verified : undefined,
      name: typeof name === 'string' ? name : undefined,
    };
  }

  private async keys(refresh: boolean): Promise<Jwk[]> {
    if (refresh) this.jwks = undefined;
    this.jwks ??= (async () => {
      const meta = await this.discover();
      const response = await this.fetchImpl(meta.jwks_uri, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(10_000),
      });
      const doc = await json(response, 'jwks_uri');
      if (!Array.isArray(doc.keys)) throw new OidcError('jwks_uri returned no keys');
      return doc.keys as Jwk[];
    })().catch((error: unknown) => {
      this.jwks = undefined;
      throw error;
    });
    return this.jwks;
  }

  /** Verify an ID token's signature (against jwks_uri) and its claims (OIDC Core §3.1.3.7). */
  async verifyIdToken(
    token: string,
    meta: ProviderMetadata,
    nonce: string,
    now: number = Date.now(),
  ): Promise<Record<string, unknown>> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new OidcError('id_token is not a compact JWS');
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    } catch {
      throw new OidcError('id_token is not valid JSON');
    }
    const alg = typeof header.alg === 'string' ? header.alg : '';
    const algorithm = ALGORITHMS[alg];
    if (algorithm === undefined)
      throw new OidcError(`id_token alg ${JSON.stringify(alg)} is not accepted`);
    const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`);
    const signature = Buffer.from(encodedSignature, 'base64url');
    const kid = typeof header.kid === 'string' ? header.kid : undefined;
    const matches = (keys: Jwk[]) =>
      keys.filter(
        (key) =>
          (kid === undefined || key.kid === kid) &&
          (key.use === undefined || key.use === 'sig') &&
          (key.alg === undefined || key.alg === alg),
      );
    let candidates = matches(await this.keys(false));
    if (candidates.length === 0) candidates = matches(await this.keys(true)); // key rotation
    const valid = candidates.some((jwk) => {
      try {
        const key = createPublicKey({ key: jwk, format: 'jwk' });
        return verify(algorithm.hash, signed, { key, ...algorithm.options }, signature);
      } catch {
        return false;
      }
    });
    if (!valid) throw new OidcError('id_token signature is invalid');

    if (claims.iss !== meta.issuer) throw new OidcError('id_token iss does not match the issuer');
    const aud = claims.aud;
    const audiences = Array.isArray(aud) ? aud : [aud];
    if (!audiences.includes(this.clientId))
      throw new OidcError('id_token aud does not include this client');
    if (audiences.length > 1 && claims.azp !== this.clientId) {
      throw new OidcError('id_token azp is not this client');
    }
    const seconds = Math.floor(now / 1000);
    if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS < seconds) {
      throw new OidcError('id_token is expired');
    }
    if (typeof claims.iat !== 'number' || claims.iat - CLOCK_SKEW_SECONDS > seconds) {
      throw new OidcError('id_token iat is in the future');
    }
    if (claims.nonce !== nonce) throw new OidcError('id_token nonce does not match');
    return claims;
  }
}

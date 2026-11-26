# @louisremi/dsh-oidc-login

Sign in to [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
`dsh web` with any **OpenID Connect** provider, for example a self-hosted
[Pocket ID](https://pocket-id.org) (passkeys) or [Authelia](https://www.authelia.com).
- An allowed e-mail gets a **signed session cookie owned by this plugin**. dsh
  accepts it through an authentication provider the plugin registers with
  `connection.authentication`. dsh 0.2.3's own remote login uses the same
  mechanism. Nothing in dsh is patched, the plugin never reads the launch
  token, and dsh's Host/Origin checks still apply to every route.
- **dsh's own sign-in keeps working**: the `/` page (paste the token link, or
  device pairing), QR invitations from Settings → Remote connection, and the
  `?token=` link. Use them when the provider is down.
- **Inert until configured.** Without `DSH_OIDC_ISSUER` it only logs
  `oidc-login: not configured` and registers nothing but `/auth/status`. An
  invalid configuration (e.g. an empty allow-list) **fails closed**: no
  sign-in route and no provider.
- Zero runtime dependencies (`fetch` + `node:crypto`). Requires dsh ≥ 0.2.3-alpha.2.

## Configuration

Environment variables (or the same keys in the plugin's cordis config:
`issuer`, `clientId`, `clientSecretFile`, `publicUrl`, `allowedEmails`,
`sessionDays`, `requireVerifiedEmail`, `scopes`):

| Variable                          | Required | Meaning                                                                                                                                |
| --------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `DSH_OIDC_ISSUER`                 | yes      | Provider issuer URL, `https://` (e.g. `https://auth.example.com`). Discovery is read from `<issuer>/.well-known/openid-configuration`. |
| `DSH_OIDC_CLIENT_ID`              | yes      | The client registered for dsh at the provider.                                                                                         |
| `DSH_OIDC_CLIENT_SECRET_FILE`     | yes¹     | File holding the client secret (e.g. a Docker secret).                                                                                 |
| `DSH_OIDC_PUBLIC_URL`             | yes      | dsh's external origin as the browser sees it, e.g. `https://dsh.example.com`. The redirect URI to register is `<this>/auth/callback`.  |
| `DSH_OIDC_ALLOWED_EMAILS`         | yes      | Comma-separated e-mails allowed to sign in (case-insensitive). Empty = disabled.                                                       |
| `DSH_OIDC_SESSION_DAYS`           | no       | Lifetime of a sign-in, in whole days (1–365, default 30), independent of the provider's own session.                                   |
| `DSH_OIDC_REQUIRE_VERIFIED_EMAIL` | no       | `0` accepts an identity the provider marks `email_verified: false` (see below).                                                        |

¹ `DSH_OIDC_CLIENT_SECRET` (inline) is accepted as a fallback. Either way the
plugin deletes `DSH_OIDC_CLIENT_SECRET` from dsh's environment at start-up so
the agent's tool subprocesses do not inherit it.

Register the client at the provider as a **confidential** client:
authorization-code grant, PKCE `S256` required, `client_secret_basic`, scopes
`openid email profile`, redirect URI `<DSH_OIDC_PUBLIC_URL>/auth/callback`.

## Routes

| Route                | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /auth/login`    | Starts the authorization-code flow (state + nonce + PKCE S256; the state is bound to a short-lived `HttpOnly` cookie). Returns a 503 page if the provider is unreachable.                                                                                                                                                                                                                                                                              |
| `GET /auth/callback` | Checks the state against this browser's cookie (single use) and exchanges the code. It **verifies the ID token signature** against the provider's JWKS, checks `iss`/`aud`/`azp`/`exp`/`iat`/`nonce`, and checks that UserInfo's `sub` matches. Then it requires the e-mail to be allowed (and not explicitly unverified). Only then does it set the session cookie and redirect to `/`. Anything else gets a generic 403; the reason goes to the log. |
| `GET /auth/logout`   | Clears this plugin's cookie and dsh's own token and QR/pairing cookies in this browser, then ends the provider session (`end_session_endpoint`) when the provider offers one.                                                                                                                                                                                                                                                                          |

The plugin does not touch `/`. Since 0.2.3, dsh serves its own sign-in page
there. **Bookmark `<DSH_OIDC_PUBLIC_URL>/auth/login`** (and install the PWA from
dsh once signed in).

Sign-in only works on the host of `DSH_OIDC_PUBLIC_URL`. The session is bound to
that authority, so other addresses (the container IP, a LAN name) only offer
dsh's own sign-in.

## The session

- Cookie `dsh-oidc-<base64url(sha256(host))>`, `HttpOnly; SameSite=Lax; Path=/`,
  plus `Secure` when the public URL is `https:`. Its value is
  `v1.<payload>.<HMAC-SHA256>`; the payload holds the authority, the e-mail and
  the issue and expiry times.
- The signing key is a 32-byte secret in dsh's credential store, record
  `oidc-login/browser-session`. It is created on first start and reused after
  restarts.
- Every request re-checks the e-mail against `DSH_OIDC_ALLOWED_EMAILS`, so
  **removing an address revokes its sessions** at the next restart (the
  allow-list is read at start-up).
- To **revoke every OIDC session**, delete the `oidc-login/browser-session`
  credential and restart dsh.

## Sign out in the settings page

The plugin ships a client half: a **Sign out** row at the end of **Settings →
General** that links to `/auth/logout`. It renders only when `/auth/status`
reports the Host half configured, and it lives in the `settings.general.item`
slot, so it follows the host's theme and disappears with the settings page.

It signs out **this browser**: dsh has no server-side session store, so other
devices keep their cookie until it expires (see [The session](#the-session) to revoke all of them).

## `email_verified` and self-hosted providers

Pocket ID sets `email_verified: true` only on self-signup or when an admin ticks
the address; the first account created at `/setup` is marked unverified unless
you tick it. Because this plugin refuses an unverified identity by default,
such a login fails with `… is not verified by the provider`. Either verify the
address in the provider, or set `DSH_OIDC_REQUIRE_VERIFIED_EMAIL=0` — the
allow-list still decides who gets in.

## dsh compatibility

0.3.0 requires dsh **0.2.3-alpha.2 or later**. dsh 0.2.3 moved browser
authentication into pluggable providers (`connection.authentication`) and
added its own remote login, which owns `/`. Plugin 0.2.x replayed dsh's
launch-token exchange and registered `/` itself. On dsh 0.2.3 that collision
stopped dsh's remote-connection plugin from loading
(`webserver: duplicate exact route "/"`). 0.3.0 registers a provider instead
and leaves `/` to dsh. On dsh ≤ 0.2.2, use plugin 0.2.1.

`DSH_OIDC_REDIRECT_ROOT` / `redirectRoot` was removed. If it is still set, the
plugin logs a warning and ignores it.

## Limits

- dsh shows no "Sign in with OIDC" button on its `/` page, which has no
  extension slot. Link or bookmark `/auth/login`.
- Logout signs out **this browser** only. To revoke every device, see
  [The session](#the-session).
- The agent running in dsh acts with the owner's authority and can read
  whatever dsh can, including the client secret file if the sandbox can reach
  it. Keep the secret outside the workspace.

## Development

```bash
npm ci
npm run lint && npm run check && npm test
npm run test:e2e   # boots the `dsh` on PATH with this plugin and a mock provider
```

MIT licensed.

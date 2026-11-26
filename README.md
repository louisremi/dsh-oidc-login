# @louisremi/dsh-oidc-login

Sign in to [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
`dsh web` with any **OpenID Connect** provider, for example a self-hosted
[Authelia](https://www.authelia.com) (email + password + passkey/TOTP), instead
of the `?token=` link printed by `dsh web`.
- A successful login for an **allowed e-mail** gets dsh's **own** signed
  session cookie, exactly as if the token link had been opened. Nothing in dsh
  is patched; the `/api` Host/Origin fence and cookie checks stay dsh's.
- The **token link keeps working**: it is the break-glass path when the
  provider is down.
- **Inert until configured.** Without `DSH_OIDC_ISSUER` it only logs
  `oidc-login: not configured; token login only` and registers nothing. An
  invalid configuration (e.g. an empty allow-list) **fails closed**: no
  sign-in route, token link only.
- Zero runtime dependencies (`fetch` + `node:crypto`).

## Configuration

Environment variables (or the same keys in the plugin's cordis config:
`issuer`, `clientId`, `clientSecretFile`, `publicUrl`, `allowedEmails`,
`redirectRoot`, `scopes`):

| Variable                      | Required | Meaning                                                                                                                                |
| ----------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `DSH_OIDC_ISSUER`             | yes      | Provider issuer URL, `https://` (e.g. `https://auth.example.com`). Discovery is read from `<issuer>/.well-known/openid-configuration`. |
| `DSH_OIDC_CLIENT_ID`          | yes      | The client registered for dsh at the provider.                                                                                         |
| `DSH_OIDC_CLIENT_SECRET_FILE` | yes¹     | File holding the client secret (e.g. a Docker secret).                                                                                 |
| `DSH_OIDC_PUBLIC_URL`         | yes      | dsh's external origin as the browser sees it, e.g. `https://dsh.example.com`. The redirect URI to register is `<this>/auth/callback`.  |
| `DSH_OIDC_ALLOWED_EMAILS`     | yes      | Comma-separated e-mails allowed to sign in (case-insensitive). Empty = disabled.                                                       |
| `DSH_OIDC_REDIRECT_ROOT`      | no       | `0` stops sending unauthenticated browser visits of `/` to the sign-in page.                                                           |

¹ `DSH_OIDC_CLIENT_SECRET` (inline) is accepted as a fallback. Either way the
plugin deletes `DSH_OIDC_CLIENT_SECRET` from dsh's environment at start-up so
the agent's tool subprocesses do not inherit it.

Register the client at the provider as a **confidential** client:
authorization-code grant, PKCE `S256` required, `client_secret_basic`, scopes
`openid email profile`, redirect URI `<DSH_OIDC_PUBLIC_URL>/auth/callback`.

## Routes

| Route                | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /auth/login`    | Starts the authorization-code flow (state + nonce + PKCE S256; state bound to a short-lived `HttpOnly` cookie). 503 page if the provider is unreachable.                                                                                                                                                                                                                                                                |
| `GET /auth/callback` | Checks the state against this browser's cookie (once only), exchanges the code, **verifies the ID token signature** against the provider's JWKS and its `iss`/`aud`/`azp`/`exp`/`iat`/`nonce`, checks that UserInfo's `sub` matches, then requires the e-mail to be allowed (and not explicitly unverified). Only then does it hand out dsh's session cookie. Anything else: a generic 403, the reason goes to the log. |
| `GET /auth/logout`   | Clears dsh's cookie in this browser and ends the provider session (`end_session_endpoint`) when the provider offers one.                                                                                                                                                                                                                                                                                                |
| `GET /`              | dsh's own index handling, except that a **browser navigation** that would get dsh's bare 401 is redirected to `/auth/login`. Token links, valid cookies, API clients and health checks behave exactly as without the plugin.                                                                                                                                                                                            |

Sign-in only works on the host of `DSH_OIDC_PUBLIC_URL`: dsh binds its
cookie to the request's Host, so other addresses (the container IP, a LAN
name) keep dsh's plain 401 and the token link.

## Sign out in the settings page

The plugin ships a client half: a **Sign out** row at the end of **Settings →
General** that links to `/auth/logout`. It renders only when `/auth/status`
reports the Host half configured, and it lives in the `settings.general.item`
slot, so it follows the host's theme and disappears with the settings page.

It signs out **this browser**: dsh has no server-side session store, so other
devices keep their cookie until it expires (delete dsh's
`client-connection/browser-session` credential to revoke all of them).

## `email_verified` and self-hosted providers

Pocket ID sets `email_verified: true` only on self-signup or when an admin ticks
the address; the first account created at `/setup` is marked unverified unless
you tick it. Because this plugin refuses an unverified identity by default,
such a login fails with `… is not verified by the provider`. Either verify the
address in the provider, or set `DSH_OIDC_REQUIRE_VERIFIED_EMAIL=0` — the
allow-list still decides who gets in.

## dsh compatibility

dsh 0.2.3 moved browser authentication out of the connection service into the
Token Provider plugin (`@deepseek-ai/dsh-host-authentication-token`; dsh's
upgrade guide `v0.2.2-rc.2/connection-page-peer`). This plugin supports both
and picks one at start-up (`src/dsh-auth.ts`):
- **up to 0.2.2:** `connection.authorizeIndex` and `connection.authenticatedUrl`;
- **0.2.3 and later:** only public surfaces. The launch token comes from the
  URL the Token Provider adds to `webserver/entry-url`, and the cookie from
  replaying `/?token=` through the `webserver/request` middleware. The `/`
  decision is `webServer.authorize`, the same admission dsh applies to its own
  routes. The `/auth/*` routes are registered `auth: 'anonymous'`, since dsh
  0.2.3 routes require a session by default.

With neither API, the plugin logs `oidc-login: disabled, this dsh lacks the
connection/webServer APIs it needs` and registers no sign-in route; the token
link keeps working.

## Limits

- dsh has no server-side session store: logout clears the browser's cookie
  only. To revoke every session at once, delete dsh's
  `client-connection/browser-session` credential and restart dsh.
- The dsh session lasts dsh's `cookieMaxAgeDays` (30 days by default),
  independently of the provider's own session. Since dsh 0.2.3 that setting
  belongs to the `authentication-token` plugin's config, not `connection`'s.
- The agent running in dsh acts with the owner's authority and can read
  whatever dsh can, including the client secret file if it is mounted where
  the sandbox lets it read. Keep the secret outside the workspace.

## Development

```bash
npm ci
npm run lint && npm run check && npm test
npm run test:e2e   # boots the `dsh` on PATH with this plugin and a mock provider
```

MIT licensed.

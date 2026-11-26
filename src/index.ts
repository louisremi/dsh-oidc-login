import { type RawConfig, resolveConfig } from './config.ts';
import type { Logger, PluginContext } from './context.ts';
import { OidcClient } from './oidc.ts';
import { CALLBACK_PATH, LOGIN_PATH, LOGOUT_PATH, LoginRoutes } from './routes.ts';
import { BrowserSessions, CREDENTIAL_KEY, loadSigningKey } from './session.ts';

export const name = 'oidc-login';

/** Services needed before the routes and the authentication provider can be registered (dsh 0.2.3+). */
export const inject = ['webServer', 'connection', 'connection.authentication', 'credentials'];

const consoleLogger: Logger = {
  info: (...args) => console.log(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args),
};

/**
 * Sign in to dsh web with any OpenID Connect provider (e.g. Pocket ID).
 * A successful login for an allowed e-mail receives this plugin's own signed
 * session cookie, which dsh accepts through the authentication provider
 * registered here: the same seam dsh's own remote login (QR, pairing) uses.
 * dsh's `/` sign-in page, its token link and its remote login keep working.
 * Inert until DSH_OIDC_ISSUER is set.
 */
export async function apply(ctx: PluginContext, raw?: RawConfig): Promise<void> {
  const logger = ctx.logger ?? consoleLogger;
  const result = resolveConfig(raw);
  // The browser half asks this before offering its "Sign out" row, so an
  // installed-but-unconfigured plugin adds no UI.
  const enabled = result.kind === 'enabled';
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: '/auth/status',
        auth: 'anonymous',
        handler: (_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end(JSON.stringify({ enabled }));
        },
      }),
    'oidc-login: /auth/status',
  );
  if (result.kind === 'disabled') {
    logger.info(`oidc-login: not configured (${result.reason}); dsh's own sign-in only`);
    return;
  }
  if (result.kind === 'invalid') {
    // Fail closed: no sign-in route exists, dsh's own sign-in still works.
    logger.error(`oidc-login: disabled, configuration is invalid: ${result.reason}`);
    return;
  }
  const { config } = result;
  for (const warning of result.warnings) logger.warn(`oidc-login: ${warning}`);

  let key: Buffer;
  try {
    key = await loadSigningKey(ctx.credentials);
  } catch (error) {
    logger.error(
      `oidc-login: disabled, cannot load the ${CREDENTIAL_KEY} signing key:`,
      error instanceof Error ? error.message : error,
    );
    return;
  }
  const sessions = new BrowserSessions(key, config);
  const peer = ctx.connection.createPeer({ principal: { kind: 'owner' } });
  ctx.effect(
    () =>
      ctx.connection.authentication.register({
        authenticate: (request) => (sessions.verify(request) === undefined ? undefined : peer),
      }),
    'oidc-login: authentication provider',
  );

  const oidc = new OidcClient(config.issuer, config.clientId, config.clientSecret);
  const routes = new LoginRoutes({ config, oidc, sessions, logger });
  // These are the sign-in endpoints, so they are anonymous (dsh requires a session by default).
  const register = (path: string, handler: LoginRoutes['login']) =>
    ctx.effect(
      () => ctx.webServer.register({ kind: 'exact', path, handler, auth: 'anonymous' }),
      `oidc-login: ${path}`,
    );
  register(LOGIN_PATH, routes.login);
  register(CALLBACK_PATH, routes.callback);
  register(LOGOUT_PATH, routes.logout);
  // Warm the discovery cache so a misconfigured issuer shows up in the logs at start-up.
  oidc.discover().then(
    () =>
      logger.info(
        `oidc-login: sign-in enabled at ${config.publicUrl}${LOGIN_PATH} (issuer ${config.issuer})`,
      ),
    (error: unknown) =>
      logger.warn(
        `oidc-login: issuer ${config.issuer} is not reachable yet; sign-in will retry on demand`,
        error instanceof Error ? error.message : error,
      ),
  );
}

import { type RawConfig, resolveConfig } from './config.ts';
import type { Logger, PluginContext } from './context.ts';
import { OidcClient } from './oidc.ts';
import { CALLBACK_PATH, LOGIN_PATH, LOGOUT_PATH, LoginRoutes } from './routes.ts';

export const name = 'oidc-login';

/** Services needed before the routes can be registered. */
export const inject = ['webServer', 'connection'];

const consoleLogger: Logger = {
  info: (...args) => console.log(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args),
};

/**
 * Sign in to dsh web with any OpenID Connect provider (e.g. a self-hosted
 * Authelia). A successful login for an allowed e-mail receives dsh's own
 * signed session cookie, exactly as if the launch-token link had been
 * opened; the token link keeps working. Inert until DSH_OIDC_ISSUER is set.
 */
export function apply(ctx: PluginContext, raw?: RawConfig): void {
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
        handler: (_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          res.end(JSON.stringify({ enabled }));
        },
      }),
    'oidc-login: /auth/status',
  );
  if (result.kind === 'disabled') {
    logger.info(`oidc-login: not configured (${result.reason}); token login only`);
    return;
  }
  if (result.kind === 'invalid') {
    // Fail closed: no sign-in route exists, the token link still works.
    logger.error(`oidc-login: disabled, configuration is invalid: ${result.reason}`);
    return;
  }
  const { config } = result;
  const { connection, webServer } = ctx;
  if (
    typeof connection.authorizeIndex !== 'function' ||
    typeof connection.authenticatedUrl !== 'function' ||
    typeof webServer.readResource !== 'function'
  ) {
    logger.error('oidc-login: disabled, this dsh lacks the connection/webServer APIs it needs');
    return;
  }
  const oidc = new OidcClient(config.issuer, config.clientId, config.clientSecret);
  const routes = new LoginRoutes({
    config,
    oidc,
    connection: ctx.connection,
    webServer: ctx.webServer,
    logger,
  });
  const register = (path: string, handler: LoginRoutes['login']) =>
    ctx.effect(
      () => ctx.webServer.register({ kind: 'exact', path, handler }),
      `oidc-login: ${path}`,
    );
  register(LOGIN_PATH, routes.login);
  register(CALLBACK_PATH, routes.callback);
  register(LOGOUT_PATH, routes.logout);
  if (config.redirectRoot) register('/', routes.root);
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

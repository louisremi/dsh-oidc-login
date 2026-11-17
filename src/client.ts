/**
 * Client half of dsh-oidc-login: a "Sign out" row on the General settings page.
 *
 * This file is a classic script, not a module: dsh serves `exports["./client"]`
 * verbatim to the browser, which registers it through `window.__ModuleLoader__`.
 * It must keep no top-level `import`/`export`; TypeScript only adds types here.
 *
 * The row is hidden unless the Host half answers its status route, so a plugin
 * that is installed but not configured (no DSH_OIDC_ISSUER) adds no UI.
 */

/** The loader dsh's page runtime installs before loading plugin clients. */
interface OidcModuleLoader {
  load(entry: { id: string; factory(require: (specifier: string) => unknown): unknown }): void;
}

const loader = (window as unknown as { __ModuleLoader__: OidcModuleLoader }).__ModuleLoader__;

loader.load({
  id: '@louisremi/dsh-oidc-login',
  factory(require: (specifier: string) => unknown) {
    const React = require('react') as {
      createElement(type: unknown, props?: unknown, ...children: unknown[]): unknown;
      useEffect(effect: () => unknown, deps?: unknown[]): void;
      useState<T>(initial: T): [T, (next: T) => void];
    };
    const h = React.createElement;
    const NS = 'oidc-login';
    const STATUS_ROUTE = '/auth/status';
    const LOGOUT_ROUTE = '/auth/logout';

    const en = {
      'signOut.title': 'Sign out',
      'signOut.description':
        'Ends the session in this browser and returns you to the sign-in page. Other devices stay signed in.',
      'signOut.action': 'Sign out',
    };

    type Translate = (key: string, params?: Record<string, unknown>) => string;

    /** `settings.general.item` row; hidden until the Host confirms sign-in is configured. */
    function SignOutRow({ t }: { t?: Translate }) {
      const translate: Translate = t ?? ((key) => (en as Record<string, string>)[key] ?? key);
      const [enabled, setEnabled] = React.useState<boolean | undefined>(undefined);

      React.useEffect(() => {
        let cancelled = false;
        fetch(STATUS_ROUTE, { headers: { accept: 'application/json' } })
          .then((response) => (response.ok ? response.json() : { enabled: false }))
          .then((body: { enabled?: boolean }) => {
            if (!cancelled) setEnabled(body.enabled === true);
          })
          .catch(() => {
            if (!cancelled) setEnabled(false);
          });
        return () => {
          cancelled = true;
        };
      }, []);

      if (enabled !== true) return null;

      return h(
        'div',
        {
          style: {
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
            padding: '0.75rem 0',
            borderBottom: '0.5px solid var(--dsw-alias-border-l2)',
          },
        },
        h(
          'div',
          { style: { display: 'flex', flexDirection: 'column', gap: '0.125rem' } },
          h('span', { style: { fontWeight: 600 } }, translate('signOut.title')),
          h(
            'span',
            { style: { fontSize: '0.875em', opacity: 0.7 } },
            translate('signOut.description'),
          ),
        ),
        h(
          'a',
          {
            href: LOGOUT_ROUTE,
            style: {
              flex: 'none',
              padding: '0.375rem 0.75rem',
              borderRadius: '0.375rem',
              border: '0.5px solid var(--dsw-alias-border-l2)',
              color: 'inherit',
              textDecoration: 'none',
              fontSize: '0.875em',
            },
          },
          translate('signOut.action'),
        ),
      );
    }

    interface ClientCtx {
      effect(callback: () => unknown, label?: string): unknown;
      slots: {
        inject(name: string, factory: () => unknown): unknown;
        register(
          registration: { name: string; id?: string; order?: number; locale?: string },
          component: unknown,
        ): unknown;
      };
      locale: {
        register(namespace: string, dictionaries: Record<string, Record<string, string>>): unknown;
      };
    }

    return {
      // Client services this plugin reads; without them the loader refuses to
      // activate it ("cannot get property \"locale\" without inject").
      inject: ['slots', 'locale'],
      apply(ctx: ClientCtx) {
        ctx.effect(() => ctx.locale.register(NS, { en }), 'oidc-login: dictionaries');
        ctx.slots.inject('settings.general.item', () =>
          ctx.slots.register(
            { name: 'settings.general.item', id: 'oidc-sign-out', order: 20, locale: NS },
            SignOutRow,
          ),
        );
      },
    };
  },
});

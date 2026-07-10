// Runtime configuration. In production the nginx entrypoint writes
// `window.__CONFIG__` from container env (see docker/frontend-entrypoint.sh),
// so the same image is reused across environments without a rebuild. In dev,
// public/config.js provides the LocalDev default and Vite env vars are a
// fallback.

export type AuthMode = "oidc" | "localdev";

interface AppConfig {
  authMode: AuthMode;
  oidcAuthority?: string;
  oidcClientId?: string;
  oidcScope: string;
  apiBase: string;
}

interface WindowConfig {
  authMode?: string;
  oidcAuthority?: string;
  oidcClientId?: string;
  oidcScope?: string;
  apiBase?: string;
}

const runtime: WindowConfig =
  (window as unknown as { __CONFIG__?: WindowConfig }).__CONFIG__ ?? {};

export const config: AppConfig = {
  authMode:
    (runtime.authMode as AuthMode) ??
    (import.meta.env.VITE_AUTH_MODE as AuthMode) ??
    "localdev",
  oidcAuthority: runtime.oidcAuthority || import.meta.env.VITE_OIDC_AUTHORITY,
  oidcClientId: runtime.oidcClientId || import.meta.env.VITE_OIDC_CLIENT_ID,
  oidcScope:
    runtime.oidcScope || import.meta.env.VITE_OIDC_SCOPE || "openid profile",
  apiBase: runtime.apiBase ?? import.meta.env.VITE_API_BASE ?? "",
};

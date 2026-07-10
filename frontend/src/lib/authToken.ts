// Bridges the OIDC auth context (a React hook) to the plain modules that make
// requests (api.ts, signalr.ts). The auth gate registers a getter; requests
// read the current access token from it. In LocalDev mode no getter is set and
// the getter returns null, so requests carry no bearer token.

type TokenGetter = () => string | null | undefined;

let getter: TokenGetter | null = null;

export function setAccessTokenGetter(fn: TokenGetter | null): void {
  getter = fn;
}

export function getAccessToken(): string | null {
  return getter?.() ?? null;
}

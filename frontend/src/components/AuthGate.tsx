import { useEffect } from "react";
import type { ReactNode } from "react";
import { useAuth } from "react-oidc-context";
import { setAccessTokenGetter } from "../lib/authToken";

/**
 * Gates the app behind OIDC sign-in and bridges the access token to the request
 * modules. Only rendered when auth mode is "oidc" (wrapped in AuthProvider);
 * LocalDev mode renders the app directly with no token.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const auth = useAuth();

  // Keep the request modules' token getter pointed at the current access token.
  useEffect(() => {
    setAccessTokenGetter(() => auth.user?.access_token);
    return () => setAccessTokenGetter(null);
  }, [auth.user]);

  // Kick off sign-in once when unauthenticated.
  useEffect(() => {
    if (!auth.isLoading && !auth.isAuthenticated && !auth.activeNavigator && !auth.error) {
      void auth.signinRedirect();
    }
  }, [auth.isLoading, auth.isAuthenticated, auth.activeNavigator, auth.error, auth]);

  if (auth.error) {
    return (
      <CenterMessage
        title="Sign-in failed"
        detail={auth.error.message}
        action={{ label: "Retry", onClick: () => void auth.signinRedirect() }}
      />
    );
  }
  if (auth.isLoading || !auth.isAuthenticated) {
    return <CenterMessage title="Signing in…" />;
  }
  return <>{children}</>;
}

/** Sign-out control; safe to use only inside AuthProvider (OIDC mode). */
export function OidcSignOut() {
  const auth = useAuth();
  const name =
    (auth.user?.profile?.name as string | undefined) ??
    (auth.user?.profile?.preferred_username as string | undefined);
  return (
    <button
      onClick={() => void auth.signoutRedirect()}
      className="text-left text-[11px] text-slate-500 hover:text-slate-300"
    >
      Sign out{name ? ` · ${name}` : ""}
    </button>
  );
}

function CenterMessage({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="text-center">
        <div className="mb-2 flex justify-center">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-600 text-sm font-bold text-white">
            PS
          </div>
        </div>
        <div className="text-sm font-medium text-slate-200">{title}</div>
        {detail && <div className="mt-1 max-w-sm text-xs text-slate-500">{detail}</div>}
        {action && (
          <button
            onClick={action.onClick}
            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500"
          >
            {action.label}
          </button>
        )}
      </div>
    </div>
  );
}

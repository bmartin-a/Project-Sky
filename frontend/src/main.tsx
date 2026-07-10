import { StrictMode } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AuthProvider } from "react-oidc-context";
import { WebStorageStateStore } from "oidc-client-ts";
import Layout from "./components/Layout";
import { AuthGate } from "./components/AuthGate";
import { config } from "./lib/config";
import Dashboard from "./pages/Dashboard";
import ScansPage from "./pages/ScansPage";
import ScanDetailPage from "./pages/ScanDetailPage";
import TargetsPage from "./pages/TargetsPage";
import ScanPoliciesPage from "./pages/ScanPoliciesPage";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:scanId", element: <ScanDetailPage /> },
      { path: "targets", element: <TargetsPage /> },
      { path: "policies", element: <ScanPoliciesPage /> },
    ],
  },
]);

const app: ReactNode = (
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
  </QueryClientProvider>
);

const root = createRoot(document.getElementById("root")!);

if (config.authMode === "oidc") {
  const oidcConfig = {
    authority: config.oidcAuthority ?? "",
    client_id: config.oidcClientId ?? "",
    redirect_uri: window.location.origin,
    post_logout_redirect_uri: window.location.origin,
    scope: config.oidcScope,
    response_type: "code",
    userStore: new WebStorageStateStore({ store: window.localStorage }),
    automaticSilentRenew: true,
    onSigninCallback: () =>
      window.history.replaceState({}, document.title, window.location.pathname),
  };
  root.render(
    <StrictMode>
      <AuthProvider {...oidcConfig}>
        <AuthGate>{app}</AuthGate>
      </AuthProvider>
    </StrictMode>,
  );
} else {
  // LocalDev: no auth provider; the API authenticates every request.
  root.render(<StrictMode>{app}</StrictMode>);
}

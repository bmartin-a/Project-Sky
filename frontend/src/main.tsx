import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Layout from "./components/Layout";
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

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);

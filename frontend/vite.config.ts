import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// The dev server runs on 3000 to match the API's CORS allowlist.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    host: true,
    proxy: {
      // Proxy API + SignalR to the backend during development.
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/hubs": { target: "http://localhost:8080", ws: true, changeOrigin: true },
    },
  },
});

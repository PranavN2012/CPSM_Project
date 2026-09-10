import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// API routes proxied to scripts/local-api-server.py during `npm run dev`.
// After `npm run build`, local-api-server.py serves the built dist/ directly
// (same origin), so no proxy is needed in that mode.
const API_ROUTES = [
  "/events",
  "/stats",
  "/compliance",
  "/trends",
  "/report",
  "/create-issues",
  "/policies",
  "/providers",
  "/scan",
];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      API_ROUTES.map((route) => [
        route,
        { target: "http://localhost:3001", changeOrigin: true },
      ])
    ),
  },
  build: {
    outDir: "dist",
  },
});

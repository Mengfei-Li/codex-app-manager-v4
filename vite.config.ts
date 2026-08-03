import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

import pkg from "./package.json";

export default defineConfig({
  plugins: [react()],
  define: {
    "import.meta.env.VITE_APP_VERSION": JSON.stringify(pkg.version),
  },
  clearScreen: false,
  test: {
    exclude: [...configDefaults.exclude, ".claude/**"],
    environment: "jsdom",
    // Release-invariant tests create local Git repositories and HTTP servers.
    // Five seconds is routinely insufficient on cold or virus-scanned Windows
    // hosts; keep the assertions intact while allowing deterministic cleanup.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    environmentOptions: {
      jsdom: {
        url: "http://localhost/",
      },
    },
    setupFiles: ["./vitest.setup.ts"],
    globals: false,
  },
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
});

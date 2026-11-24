import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
  test: {
    isolate: false,
    maxWorkers: 1,
    coverage: {
      provider: "istanbul",
      include: ["src/gateway/**/*.ts", "src/store/**/*.ts", "src/lib/**/*.ts"],
      thresholds: {
        statements: 90,
        branches: 90,
        "src/gateway/**/*.ts": { statements: 90, branches: 90 },
        "src/store/**/*.ts": { statements: 90, branches: 90 },
        "src/lib/**/*.ts": { statements: 90, branches: 90 },
      },
    },
  },
});

import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:3100", trace: "retain-on-failure" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: "npm run start",
    url: "http://127.0.0.1:3100/api/health",
    reuseExistingServer: false,
    env: {
      PORT: "3100",
      HOSTNAME: "127.0.0.1",
      DATABASE_URL: "",
      LOG_HASH_KEY: "",
      DOMAIN_VERIFICATION_KEY: "",
      REPORT_SIGNING_KEY: "playwright-report-signing-key-at-least-32",
      TRUST_PROXY_HEADERS: "false",
    },
  },
});

import { defineConfig, devices } from "@playwright/test";

// 에어갭/사내서버를 흉내내는 E2E: FastAPI 가 빌드된 SPA + API 를 한 오리진(8770)에 서빙하고,
// 브라우저가 실제 사용자 여정(로그인 → 대시보드 → 발견 관리)을 구동한다.
// 크로미움은 환경에 선설치된 것을 재사용(PLAYWRIGHT_CHROMIUM_PATH 가 있으면 그 경로).
const BASE_URL = process.env.SCANOPS_E2E_BASE_URL || "http://127.0.0.1:8770";
const chromiumPath = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 30_000,
  expect: { timeout: 7_000 },
  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    ...(chromiumPath ? { launchOptions: { executablePath: chromiumPath } } : {}),
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  // 저장소 밖에서 서버를 이미 띄웠다면 SCANOPS_E2E_BASE_URL 로 붙고 webServer 는 생략한다.
  webServer: process.env.SCANOPS_E2E_BASE_URL
    ? undefined
    : {
        command: "bash e2e/serve.sh",
        url: `${BASE_URL}/api/health`,
        timeout: 120_000,
        reuseExistingServer: !process.env.CI,
        stdout: "pipe",
        stderr: "pipe",
      },
});

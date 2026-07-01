/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// base './' : FastAPI 가 dist 를 어느 경로에 두든 상대경로로 자산 로드(에어갭 배포 안전).
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    // 개발 모드: /api 를 백엔드로 프록시 (프로덕션은 같은 오리진이라 불필요).
    proxy: { "/api": "http://localhost:8770" },
  },
  build: { outDir: "dist" },
  // 유닛/컴포넌트 테스트(vitest) — jsdom 환경. e2e(playwright)는 파일 규칙(e2e/**)으로 분리.
  test: {
    environment: "jsdom",
    setupFiles: "./vitest.setup.js",
    include: ["src/**/*.{test,spec}.{js,jsx}"],
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
    css: false,
    clearMocks: true,
    restoreMocks: true,
  },
});

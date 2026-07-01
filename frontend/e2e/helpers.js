import { expect } from "@playwright/test";

// serve.sh/seed.py 와 동일한 고정 자격증명(같은 환경변수 기본값).
export const ADMIN_USER = "admin";
export const ADMIN_PASSWORD = process.env.SCANOPS_E2E_PASSWORD || "scanops-e2e";

// 로그인 폼을 채우고 대시보드가 뜰 때까지 기다린다.
export async function login(page, user = ADMIN_USER, password = ADMIN_PASSWORD) {
  await page.goto("/");
  await page.getByPlaceholder("아이디").fill(user);
  await page.locator('input[type="password"]').fill(password);
  await page.getByRole("button", { name: "접속" }).click();
  await expect(page.locator(".topbar h2")).toHaveText("대시보드");
}

// 사이드바 내비게이션 항목(href 없는 <a>)을 라벨로 클릭.
export function navItem(page, label) {
  return page.locator(".nav a", { hasText: label });
}

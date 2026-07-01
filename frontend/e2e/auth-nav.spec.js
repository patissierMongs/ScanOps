import { expect, test } from "@playwright/test";

import { ADMIN_PASSWORD, ADMIN_USER, login, navItem } from "./helpers.js";

test.describe("인증 & 내비게이션", () => {
  test("잘못된 비밀번호는 로그인 실패 메시지", async ({ page }) => {
    await page.goto("/");
    await page.getByPlaceholder("아이디").fill(ADMIN_USER);
    await page.locator('input[type="password"]').fill("wrong-password");
    await page.getByRole("button", { name: "접속" }).click();
    await expect(page.locator(".lg-err")).toBeVisible();
    // 여전히 로그인 화면(접속 버튼 존재)
    await expect(page.getByRole("button", { name: "접속" })).toBeVisible();
  });

  test("로그인 → 주요 화면 이동 → 로그아웃", async ({ page }) => {
    await login(page);

    // 관리자이므로 '사용자' 메뉴까지 보인다.
    await expect(navItem(page, "사용자")).toBeVisible();

    // 상단 제목(TITLES)으로 뷰 전환을 확인.
    const routes = [
      ["발견 관리", "발견 관리"],
      ["스캔", "스캔"],
      ["히트맵", "시간축 히트맵"],
      ["규칙", "규칙"],
      ["자산대장", "자산대장"],
      ["사용자", "사용자 관리"],
      ["대시보드", "대시보드"],
    ];
    for (const [label, title] of routes) {
      await navItem(page, label).click();
      await expect(page.locator(".topbar h2")).toHaveText(title);
    }

    // 로그아웃 → 로그인 화면으로 복귀.
    await page.getByText("로그아웃").click();
    await expect(page.getByRole("button", { name: "접속" })).toBeVisible();
  });

  test("세션 토큰이 있으면 새로고침 후에도 로그인 유지", async ({ page }) => {
    await login(page);
    await page.reload();
    await expect(page.locator(".topbar h2")).toHaveText("대시보드");
    // 토큰이 localStorage 에 저장돼 있어야 한다.
    const token = await page.evaluate(() => localStorage.getItem("scanops_token"));
    expect(token, "로그인 후 scanops_token 이 저장되어야 함").toBeTruthy();

    // 참고: ADMIN_PASSWORD 는 seed 와 helper 가 공유하는 고정 자격증명.
    expect(ADMIN_PASSWORD.length).toBeGreaterThan(0);
  });
});

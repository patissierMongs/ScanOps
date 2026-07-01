import { expect, test } from "@playwright/test";

import { login, navItem } from "./helpers.js";

// 시드된 샘플 스캔은 호스트 127.0.0.1 의 열린 포트들을 발견으로 채운다.
const SEEDED_HOST = "127.0.0.1";

test.describe("발견 관리", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navItem(page, "발견 관리").click();
    await expect(page.locator(".topbar h2")).toHaveText("발견 관리");
  });

  test("시드된 발견이 표에 나타난다", async ({ page }) => {
    const table = page.locator("table.tbl");
    await expect(table).toBeVisible();
    await expect(table.getByText(SEEDED_HOST).first()).toBeVisible();
    // 데이터 행이 최소 몇 건 이상(빈 상태 아님).
    const rows = page.locator("table.tbl tbody tr");
    expect(await rows.count()).toBeGreaterThan(1);
  });

  test("검색 필터: 없는 값은 '발견 없음', 되돌리면 다시 표시", async ({ page }) => {
    const search = page.getByPlaceholder("검색 (서비스/호스트명)");
    await search.fill("존재하지않는서비스zzz");
    await search.press("Enter");
    await expect(page.getByText("발견 없음")).toBeVisible();

    await search.fill("");
    await search.press("Enter");
    await expect(page.locator("table.tbl").getByText(SEEDED_HOST).first()).toBeVisible();
  });

  test("행을 클릭하면 상세 서랍이 열린다", async ({ page }) => {
    // 0번째 셀은 체크박스(stopPropagation) → 1번째(호스트) 셀을 클릭해 서랍을 연다.
    await page.locator("table.tbl tbody tr").first().locator("td").nth(1).click();
    const drawer = page.locator(".drawer");
    await expect(drawer).toBeVisible();
    await expect(drawer.locator("h3").first()).toContainText(`${SEEDED_HOST}:`);
    await expect(drawer.getByText("변경 이력")).toBeVisible();
    await drawer.getByRole("button", { name: "닫기" }).click();
    await expect(drawer).not.toBeVisible();
  });

  test("정상처리(2단계 확인) → 완료 토스트", async ({ page }) => {
    const firstRow = page.locator("table.tbl tbody tr").first();
    await firstRow.getByRole("button", { name: "정상처리" }).click();
    // 1차 클릭은 '확인?' 로 바뀌는 2단계 가드.
    await firstRow.getByRole("button", { name: "확인?" }).click();
    await expect(page.locator(".toasts")).toContainText("정상처리 완료");
  });
});

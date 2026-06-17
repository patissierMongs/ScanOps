// 자산대장 기준 nmap 샘플 결과 화면 — 발견(매칭 부서/연락처·금지) + 자산대장.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.send("Emulation.setDeviceMetricsOverride", { width: 1480, height: 1150, deviceScaleFactor: 1.4, mobile: false });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);
const tab = (l) => c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes(${JSON.stringify(l)}))?.click(); return true;`);

// 발견 — 컬럼빌더에 연락처/부서 추가해 매칭 노출
await tab("발견");
await sleep(900);
await c.evaluate(`
  // 컬럼 팔레트에서 연락처 추가
  const add=[...document.querySelectorAll('[data-testid=cb-palette] .cb-add')].find(b=>b.innerText.includes('연락처'));
  if(add) add.click();
  return true;
`);
await sleep(500);
await c.screenshot("samples/ledger_findings.png");

await tab("자산대장");
await sleep(700);
await c.screenshot("samples/ledger_assets.png");

await tab("대시보드");
await sleep(700);
await c.screenshot("samples/ledger_dashboard.png");

const probe = await c.evaluate(`return {
  rows: document.querySelectorAll('.tbl tbody tr').length,
  banned: document.querySelectorAll('.pill.banned').length
};`);
console.log("probe:", JSON.stringify(probe), "errors:", c.consoleMsgs.filter(m=>m.type==='error').length);
c.close();

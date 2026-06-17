// 실 스캔 데이터가 담긴 ScanOps 화면 캡처 — 대시보드 + 발견 관리.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 960, deviceScaleFactor: 1.6, mobile: false });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1600);

const tab = (l) => c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes(${JSON.stringify(l)}))?.click(); return true;`);

await tab("대시보드");
await sleep(900);
await c.screenshot("samples/live_dashboard.png");

await tab("발견 관리");
await sleep(1100);
await c.screenshot("samples/live_findings.png");

await tab("위험 규칙");
await sleep(700);
await c.screenshot("samples/live_rules.png");

const probe = await c.evaluate(`return { rows: document.querySelectorAll('.tbl tbody tr').length, h2: document.querySelector('.main h2')?.innerText };`);
console.log("probe:", JSON.stringify(probe));
console.log("console errors:", c.consoleMsgs.filter(m=>m.type==='error').length, "exceptions:", c.exceptions.length);
c.close();

// 신기능 스크린샷 — 스캔 옵션 빌더 / 발견 타겟 재스캔 / 금지 등급.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1100, deviceScaleFactor: 1.5, mobile: false });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);

const tab = (l) => c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes(${JSON.stringify(l)}))?.click(); return true;`);

// 스캔 탭 — 옵션 빌더 + 실시간 명령
await tab("스캔");
await sleep(700);
await c.evaluate(`
  const t=[...document.querySelectorAll('input')].find(i=>i.placeholder&&i.placeholder.includes('타겟'));
  if(t){ const set=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
    set.call(t,'10.0.12.0/24'); t.dispatchEvent(new Event('input',{bubbles:true})); }
  return true;
`);
await sleep(400);
await c.screenshot("samples/feat_scan.png");

// 발견 — 행 선택 후 타겟 재스캔 패널
await tab("발견");
await sleep(900);
await c.evaluate(`
  const cbs=[...document.querySelectorAll('.tbl tbody input[type=checkbox]')];
  cbs.slice(0,2).forEach(cb=>cb.click());
  await new Promise(r=>setTimeout(r,150));
  const b=[...document.querySelectorAll('button')].find(x=>x.innerText.includes('선택 재스캔'));
  if(b) b.click();
  return true;
`);
await sleep(900);
await c.screenshot("samples/feat_findings_rescan.png");

// 위험 규칙 — 금지
await tab("위험 규칙");
await sleep(700);
await c.screenshot("samples/feat_rules.png");

const probe = await c.evaluate(`return {
  banned: [...document.querySelectorAll('.pill.banned')].length,
  cmd: document.querySelector('.pre')?.innerText || ''
};`);
console.log("banned pills:", probe.banned);
console.log("errors:", c.consoleMsgs.filter(m=>m.type==='error').length, "exceptions:", c.exceptions.length);
c.close();

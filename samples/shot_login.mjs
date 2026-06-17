// 로그인 화면 캡처(로그아웃 상태) — 데스크탑/모바일 뷰포트 + 콘솔에러 점검.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });

async function metrics(w, h) {
  await c.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 2, mobile: false });
}

// 데스크탑
await metrics(1280, 800);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(400);
await c.evaluate(`localStorage.removeItem("scanops_token"); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1600);
await c.screenshot("samples/shot_login_desktop.png");

// 모바일
await metrics(430, 880);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);
await c.screenshot("samples/shot_login_mobile.png");

const errs = c.consoleMsgs.filter((m) => m.type === "error");
console.log("console errors:", errs.length, JSON.stringify(errs));
console.log("exceptions:", c.exceptions.length, JSON.stringify(c.exceptions));
const probe = await c.evaluate(`return { hasRadar: !!document.querySelector('.lg-radar'), word: document.querySelector('.lg-word')?.innerText||'(none)', fields: document.querySelectorAll('.lg-field').length };`);
console.log("probe:", JSON.stringify(probe));
c.close();

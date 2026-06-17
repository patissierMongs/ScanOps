// 실행 중인 ScanOps UI 를 브라우저로 열어 스크린샷 (대시보드 + 발견관리).
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const c = await connect();
await c.send("Network.enable");
await c.send("Network.setCacheDisabled", { cacheDisabled: true });

// 1) 오리진 로드 후 토큰 주입 → SPA 가 로그인 상태로 부팅
await c.navigate("http://localhost:8770/?t=" + Date.now());
await sleep(800);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate("http://localhost:8770/?t=" + Date.now());
await sleep(2500);

const title = await c.evaluate(`return document.querySelector("h2")?.innerText || document.body.innerText.slice(0,80);`);
console.log("dashboard view:", title);
await c.screenshot("samples/shot_dashboard.png");

// 2) 발견 관리 탭 클릭
await c.evaluate(`
  const a=[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes("발견"));
  if(a) a.click(); return !!a;
`);
await sleep(1500);
await c.screenshot("samples/shot_findings.png");
const rows = await c.evaluate(`return document.querySelectorAll("table tbody tr").length;`);
console.log("findings rows:", rows);

console.log("CONSOLE:", JSON.stringify(c.consoleMsgs.slice(0, 5)));
console.log("EXCEPTIONS:", JSON.stringify(c.exceptions));
c.close();

// 탭을 반복 전환하며 빈 화면/예외를 잡는다.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const c = await connect();
await c.send("Network.enable");
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.navigate("http://localhost:8770/?t=" + Date.now());
await sleep(700);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate("http://localhost:8770/?t=" + Date.now());
await sleep(2000);

const tabs = ["대시보드", "발견 관리", "스캔", "자산대장", "부서통보"];
// 빠르게 여러 번 왕복
const seq = [...tabs, ...tabs, ...tabs.slice().reverse(), ...tabs];
for (let i = 0; i < seq.length; i++) {
  const label = seq[i];
  const r = await c.evaluate(`
    const a=[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.trim()===${JSON.stringify(label)});
    if(a) a.click();
    return true;
  `);
  await sleep(180); // 일부러 짧게 — 레이스 유발
  const probe = await c.evaluate(`
    const main=document.querySelector(".main");
    const sidebar=document.querySelector(".sidebar");
    return {
      tab:${JSON.stringify(label)},
      mainLen: main ? main.innerText.trim().length : -1,
      hasSidebar: !!sidebar,
      h2: document.querySelector(".main h2")?.innerText || "(none)",
    };
  `);
  if (probe.mainLen < 5 || !probe.hasSidebar) {
    console.log("BLANK?", JSON.stringify(probe));
    await c.screenshot(`samples/blank_${i}_${probe.tab}.png`);
  }
}
await sleep(500);
console.log("EXCEPTIONS:", JSON.stringify(c.exceptions, null, 2));
console.log("CONSOLE errors:", JSON.stringify(c.consoleMsgs.filter(m => m.type === "error"), null, 2));
c.close();

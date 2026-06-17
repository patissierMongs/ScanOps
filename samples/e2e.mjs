// ScanOps 재구축 E2E — 전 탭 빈화면/콘솔/예외 0 + 컬럼빌더·내보내기 BOM·재스캔명령 검증.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.enable");
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(600);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);

const fails = [];
const tabs = ["대시보드", "발견 관리", "위험 규칙", "이력", "자산대장", "부서통보", "스캔", "사용자"];
const seq = [...tabs, ...tabs.slice().reverse(), ...tabs];

async function clickTab(label) {
  return c.evaluate(`
    const a=[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes(${JSON.stringify(label)}));
    if(a){ a.click(); return true; } return false;
  `);
}

for (let i = 0; i < seq.length; i++) {
  const label = seq[i];
  await clickTab(label);
  await sleep(160); // 짧게 — 레이스 유발
  const probe = await c.evaluate(`
    const main=document.querySelector(".main");
    return { tab:${JSON.stringify(label)}, mainLen: main?main.innerText.trim().length:-1,
             hasSidebar: !!document.querySelector(".sidebar"),
             h2: document.querySelector(".main h2")?.innerText||"(none)" };
  `);
  if (probe.mainLen < 5 || !probe.hasSidebar) {
    fails.push("BLANK " + JSON.stringify(probe));
    await c.screenshot(`samples/blank_${i}_${label}.png`);
  }
}

// ---- 컬럼 빌더 상호작용 ----
await clickTab("발견 관리");
await sleep(800);
const cb = await c.evaluate(`
  const sel=document.querySelector('[data-testid=cb-selected]');
  const before=sel.querySelectorAll('.cb-chip').length;
  const add=document.querySelector('[data-testid=cb-palette] .cb-add');
  if(add) add.click();
  await new Promise(r=>setTimeout(r,150));
  const after=document.querySelector('[data-testid=cb-selected]').querySelectorAll('.cb-chip').length;
  // 프리셋 전환(React onChange)
  const ps=document.querySelector('[data-testid=preset-select]');
  const setter=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;
  setter.call(ps,'p_finger'); ps.dispatchEvent(new Event('change',{bubbles:true}));
  await new Promise(r=>setTimeout(r,150));
  const afterPreset=document.querySelector('[data-testid=cb-selected]').querySelectorAll('.cb-chip').length;
  return { before, after, afterPreset, builderPresent: !!document.querySelector('[data-testid=column-builder]') };
`);

// ---- 재스캔 명령: 첫 행 선택 후 버튼 ----
const rescan = await c.evaluate(`
  const cbs=[...document.querySelectorAll('.tbl tbody input[type=checkbox]')];
  if(cbs[0]) cbs[0].click();
  await new Promise(r=>setTimeout(r,100));
  const btn=[...document.querySelectorAll('button')].find(b=>b.innerText.includes('재스캔 명령'));
  if(btn) btn.click();
  await new Promise(r=>setTimeout(r,400));
  const pre=document.querySelector('.pre');
  return { cmd: pre?pre.innerText:"(none)" };
`);

// ---- 내보내기 BOM (인페이지 fetch) ----
const bom = await c.evaluate(`
  const tok=localStorage.getItem('scanops_token');
  const r=await fetch('/api/findings/export?cols=host_ip,port,service&fmt=csv',{headers:{Authorization:'Bearer '+tok}});
  const buf=new Uint8Array(await r.arrayBuffer());
  return [buf[0],buf[1],buf[2]];
`);

await sleep(300);
const consoleErrors = c.consoleMsgs.filter((m) => m.type === "error");

console.log("=== RESULT ===");
console.log("blank fails:", fails.length, fails);
console.log("exceptions:", c.exceptions.length, c.exceptions);
console.log("console errors:", consoleErrors.length, JSON.stringify(consoleErrors));
console.log("column builder:", JSON.stringify(cb));
console.log("rescan cmd:", rescan.cmd);
console.log("export BOM bytes:", JSON.stringify(bom), bom[0] === 239 && bom[1] === 187 && bom[2] === 191 ? "OK(BOM)" : "NO BOM");
c.close();

// 추가 검증 — 위험규칙 UI 추가→매칭카운트, 이력 타임라인, 스크린샷.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);

const tab = (l) => c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes(${JSON.stringify(l)}))?.click(); return true;`);

// 위험 규칙: port_rule 3000 추가 → 매칭 카운트 확인
await tab("위험 규칙");
await sleep(700);
const rule = await c.evaluate(`
  const setVal=(el,val)=>{const p=el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(p,'value').set.call(el,val);
    el.dispatchEvent(new Event(el.tagName==='SELECT'?'change':'input',{bubbles:true}));};
  const kind=document.querySelector('form select');
  setVal(kind,'port_rule');
  await new Promise(r=>setTimeout(r,150));
  const portInput=document.querySelector('form input[type=number]');
  setVal(portInput,'3000');
  const addBtn=[...document.querySelectorAll('form button')].find(b=>b.innerText.includes('추가'));
  addBtn.click();
  await new Promise(r=>setTimeout(r,500));
  const rows=[...document.querySelectorAll('.tbl tbody tr')].map(tr=>tr.innerText.replace(/\\n/g,' '));
  return { rows };
`);
await c.screenshot("samples/shot_rules.png");

// 이력 타임라인
await tab("이력");
await sleep(700);
const hist = await c.evaluate(`return { events: document.querySelectorAll('.timeline .ev').length, total: document.querySelector('.panel .muted')?.innerText||document.body.innerText.match(/총 \\d+건/)?.[0]||'' };`);

// 발견 스크린샷
await tab("발견 관리");
await sleep(900);
await c.screenshot("samples/shot_findings_new.png");
await tab("자산대장");
await sleep(700);
await c.screenshot("samples/shot_assets.png");

console.log("=== RESULT2 ===");
console.log("rule rows:", JSON.stringify(rule.rows));
console.log("history events:", hist.events, hist.total);
console.log("exceptions:", c.exceptions.length, "console errors:", c.consoleMsgs.filter(m=>m.type==='error').length);
c.close();

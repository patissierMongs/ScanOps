// UC1-4: login, scan XML import (UI), asset ledger import (UI wizard), dashboard verify.
import { connect } from "./driver.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { mkdirSync } from "node:fs";
const DIR = import.meta.dirname;
const REPO = resolve(DIR, "..");
const ADMIN = process.env.SCANOPS_ADMIN_FILE || join(REPO, "data/INITIAL_ADMIN.txt");
const PW = readFileSync(ADMIN, "utf8").match(/비밀번호:\s*(\S+)/)[1];
const BASE = process.env.SCANOPS_URL || "http://127.0.0.1:8770";
const SHOT = process.env.SCANOPS_SHOTS || join(DIR, "shots"); mkdirSync(SHOT, { recursive: true });
const T = DIR;
const c = await connect();
const R = [];
const log = (uc, ok, msg) => { R.push({ uc, ok, msg }); console.log(`[${ok ? "PASS" : "FAIL"}] ${uc}: ${msg}`); };
async function tab(label) { return c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a, nav a')].find(x=>x.innerText.includes(${JSON.stringify(label)}));if(a){a.click();return true;}return false;`); }
async function apiTok() { return c.evaluate(`return localStorage.getItem('scanops_token')`); }

// ---- UC1: 로그인 ---- (clear any stored token first to test a real login)
await c.navigate(BASE + "/?t=" + Date.now()); await sleep(600);
await c.evaluate(`localStorage.removeItem('scanops_token'); return true;`);
await c.navigate(BASE + "/?t=" + Date.now()); await sleep(1200);
await c.evaluate(`
  const setN=(el,v)=>{const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};
  const ins=[...document.querySelectorAll('input')];
  setN(ins.find(i=>i.type!=='password'),'admin'); setN(ins.find(i=>i.type==='password'),${JSON.stringify(PW)});
  [...document.querySelectorAll('button')].find(b=>/접속|로그인/.test(b.innerText)).click(); return true;`);
await sleep(1800);
const li = await c.evaluate(`return {tok:!!localStorage.getItem('scanops_token'), h2:document.querySelector('.main h2')?.innerText}`);
log("UC1 로그인", li.tok && li.h2 === "대시보드", `token=${li.tok}, landed=${li.h2}`);

// ---- UC2: 스캔 XML 가져오기 (UI) ----
await tab("스캔"); await sleep(1000);
const files = ["scan_hq_datacenter", "scan_branch_office", "scan_dmz_public", "scan_ot_network", "scan_cloud_vpc"].map(f => `${T}/${f}.xml`);
const up = await c.uploadToFileInput(files, 0);  // input[0] = .xml multiple
console.log("  file set:", JSON.stringify(up));
await sleep(800);
// look for an import trigger button that appears after selecting
const impBtn = await c.evaluate(`
  const b=[...document.querySelectorAll('.main button')].find(x=>/가져오기|import|업로드|올리기|추가/.test(x.innerText) && !/폴더/.test(x.innerText));
  if(b){b.click(); return b.innerText.trim();} return '(auto or none)';`);
console.log("  import button:", impBtn);
await sleep(4000);
const tok = await apiTok();
const scans = await c.evaluate(`const r=await fetch('/api/scans',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return (await r.json()).length;`);
const fcount = await c.evaluate(`const r=await fetch('/api/findings?state=open',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return (await r.json()).length;`);
log("UC2 스캔가져오기", scans >= 5 && fcount > 300, `scans=${scans}, open findings=${fcount}`);
await c.screenshot(`${SHOT}/uc2_scans.png`);

// ---- UC3: 자산대장 가져오기 (UI 위저드) ----
await tab("자산대장"); await sleep(1000);
await c.uploadToFileInput([`${T}/assets_hq.csv`], 0);
await sleep(1500);
await c.screenshot(`${SHOT}/uc3a_wizard_step1.png`);
// advance the wizard: keep clicking forward/confirm buttons until an import happens or no progress
let wizardLog = [];
for (let step = 0; step < 8; step++) {
  const state = await c.evaluate(`
    const btns=[...document.querySelectorAll('.main button, .modal button, dialog button')].map(b=>b.innerText.trim()).filter(Boolean);
    return {btns, h:document.querySelector('.main h2,.main h3')?.innerText};
  `);
  wizardLog.push(state.btns.join("|"));
  // click the most "forward" looking button
  const clicked = await c.evaluate(`
    const prefer=[/가져오기/,/적용/,/확인/,/다음/,/불러오기/,/등록/,/저장/,/진행/];
    const btns=[...document.querySelectorAll('.main button, .modal button, dialog button')].filter(b=>b.offsetParent!==null);
    for(const re of prefer){ const b=btns.find(x=>re.test(x.innerText)&&!/취소|닫기|이전|뒤로/.test(x.innerText)); if(b){b.click(); return b.innerText.trim();}}
    return null;`);
  if (!clicked) { wizardLog.push("(no forward button)"); break; }
  wizardLog.push("->clicked:" + clicked);
  await sleep(1500);
  const done = await c.evaluate(`const r=await fetch('/api/assets',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return (await r.json()).length;`);
  if (done > 0) { wizardLog.push("assets=" + done); break; }
}
console.log("  wizard:", wizardLog.join("  ||  "));
await c.screenshot(`${SHOT}/uc3b_wizard_end.png`);
const assetN = await c.evaluate(`const r=await fetch('/api/assets',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return (await r.json()).length;`);
log("UC3 자산가져오기(UI위저드)", assetN >= 300, `assets loaded=${assetN}`);

// ---- UC4: 대시보드 지표 확인 ----
await tab("대시보드"); await sleep(1500);
const dash = await c.evaluate(`
  const txt=document.querySelector('.main')?.innerText||'';
  const r=await fetch('/api/dashboard',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});
  const d=await r.json();
  return {open:d.open_total, by_risk:d.by_risk, by_dept:d.by_dept.slice(0,4), overdue:d.overdue,
          uiHasOpen: txt.includes(String(d.open_total)) };
`);
log("UC4 대시보드", dash.open > 300 && dash.uiHasOpen, `open=${dash.open}, risk=${JSON.stringify(dash.by_risk)}, uiReflects=${dash.uiHasOpen}, topDept=${JSON.stringify(dash.by_dept[0])}`);
await c.screenshot(`${SHOT}/uc4_dashboard.png`);

console.log("\n=== SUMMARY ===");
console.log("exceptions:", c.exceptions.length, JSON.stringify(c.exceptions.slice(0, 5)));
console.log("console errors:", c.consoleMsgs.filter(m => m.type === "error").length);
console.log(JSON.stringify(R));
c.close(); process.exit(R.some(r => !r.ok) ? 1 : 0);

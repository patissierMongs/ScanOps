// UC14: 재스캔 조치검증 라이프사이클 — 실제 포트스캔 3종(base/closed/reopen)을 UI로 가져오며
// 담당배정→마감→재스캔 자동 조치검증(정상처리)→재발(REOPENED)의 핵심 루프를 검증.
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
const SC = join(REPO, "live_sample/real_scans");
const c = await connect();
const R = [];
const log = (uc, ok, msg) => { R.push({ uc, ok: !!ok, msg }); console.log(`[${ok ? "PASS" : "FAIL"}] ${uc}: ${msg}`); };
async function tab(l) { return c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a,nav a')].find(x=>x.innerText.includes(${JSON.stringify(l)}));if(a){a.click();return true}return false`); }
async function api(path) { return c.evaluate(`const r=await fetch('/api${path}',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return await r.json();`); }
async function importXml(absPath) {
  await tab("스캔"); await sleep(1000);
  await c.uploadToFileInput([absPath], 0);
  await sleep(3500); // auto-import (import-bundle)
}
async function f8085() {
  const all = await api("/findings?host=127.0.0.1&state=");  // state= empty → any
  return (all || []).find(f => f.port === 8085);
}

await c.navigate(BASE + "/?t=" + Date.now()); await sleep(1200);
if (await c.evaluate(`return !localStorage.getItem('scanops_token')`)) {
  await c.evaluate(`const setN=(el,v)=>{const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};const ins=[...document.querySelectorAll('input')];setN(ins.find(i=>i.type!=='password'),'admin');setN(ins.find(i=>i.type==='password'),${JSON.stringify(PW)});[...document.querySelectorAll('button')].find(b=>/접속|로그인/.test(b.innerText)).click();return true;`);
  await sleep(1800);
}

// (1) baseline import → 8085 & 8086 NEW_OPEN
await importXml(`${SC}/svc_base.xml`);
let f = await f8085();
log("UC14a 기준스캔 가져오기", f && f.state === "open", `8085 발견 생성=${!!f} state=${f?.state} status=${f?.status}`);

// (2) 담당 배정: 8085 → 처리중 + 마감 (드로어)
await tab("발견 관리"); await sleep(1000);
await c.evaluate(`const s=document.querySelector('.main input[placeholder*="검색"]');const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(s,'8085');s.dispatchEvent(new Event('input',{bubbles:true}));s.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));return true;`);
await sleep(1800);
const opened = await c.evaluate(`
  const rows=[...document.querySelectorAll('.main table tbody tr')];
  const row=rows.find(r=>r.innerText.includes('8085'))||rows[0];
  const cell=row?.querySelectorAll('td')[3]; if(cell)cell.click();
  await new Promise(r=>setTimeout(r,1200)); return !!document.querySelector('.drawer');
`);
if (opened) await c.evaluate(`
  const dr=document.querySelector('.drawer');
  const st=[...dr.querySelectorAll('select')].find(s=>[...s.options].some(o=>o.value==='처리중'));
  const ds=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set; ds.call(st,'처리중'); st.dispatchEvent(new Event('change',{bubbles:true}));
  await new Promise(r=>setTimeout(r,200));
  const dl=dr.querySelector('input[type=date]'); const di=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; di.call(dl,'2026-07-25'); dl.dispatchEvent(new Event('input',{bubbles:true}));
  await new Promise(r=>setTimeout(r,200));
  [...dr.querySelectorAll('button')].find(b=>b.innerText.trim()==='저장').click();
  await new Promise(r=>setTimeout(r,1000)); return true;`);
await sleep(800);
f = await f8085();
log("UC14b 담당배정(처리중+마감)", opened && f?.status === "처리중" && f?.deadline, `드로어=${opened}, status=${f?.status}, 마감=${(f?.deadline||"").slice(0,10)}`);
await c.screenshot(`${SHOT}/uc14b_assigned.png`);

// (3) 재스캔(조치완료: 8085 닫힘) 가져오기 → 자동 정상처리(조치검증) + CLOSED 이벤트
await importXml(`${SC}/svc_closed.xml`);
f = await f8085();
let ev = f ? await api(`/findings/${f.id}/events`) : [];
const hasClosed = ev.some(e => e.type === "CLOSED");
log("UC14c 재스캔 자동 조치검증", f?.state === "closed" && f?.status === "정상처리" && hasClosed,
  `8085 state=${f?.state}, status=${f?.status}(자동 정상처리), CLOSED이벤트=${hasClosed}`);
await c.screenshot(`${SHOT}/uc14c_verified_closed.png`);

// (4) 재스캔(재발: 8085 다시 열림) 가져오기 → REOPENED + 미조치 복귀 + reopened 태그
await importXml(`${SC}/svc_reopen.xml`);
f = await f8085();
ev = f ? await api(`/findings/${f.id}/events`) : [];
const hasReopen = ev.some(e => e.type === "REOPENED");
log("UC14d 재발 감지(REOPENED)", f?.state === "open" && f?.status === "미조치" && f?.reopened === 1 && hasReopen,
  `8085 state=${f?.state}, status=${f?.status}, 재발태그=${f?.reopened}, REOPENED이벤트=${hasReopen}`);
await c.screenshot(`${SHOT}/uc14d_reopened.png`);

// (5) diff API 검증 (기준 스캔 ↔ 최신 스캔)
const scans = await api("/scans");
const svcScans = scans.filter(s => /svc_/.test(s.name));
let diffOk = false, diffMsg = "diff n/a";
if (svcScans.length >= 2) {
  const target = svcScans[0].id, baseId = svcScans[svcScans.length - 1].id;
  const diff = await api(`/diff?base=${baseId}&target=${target}`);
  diffOk = !!diff && !diff.detail;
  diffMsg = `diff base#${baseId}→target#${target}: ${JSON.stringify(Object.keys(diff||{})).slice(0,80)}`;
}
log("UC14e diff API", diffOk, diffMsg);

console.log("\nPASS:", R.filter(r => r.ok).length, "/", R.length);
console.log("exceptions:", c.exceptions.length, "| console errors:", c.consoleMsgs.filter(m => m.type === "error").length);
console.log(JSON.stringify(R));
c.close(); process.exit(R.some(r => !r.ok) ? 1 : 0);

// UC8 부서통보, UC9 내보내기(감사/CSV/히트맵), UC10 사용자관리, UC11 이력, UC12 감사로그, UC13 히트맵.
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
const c = await connect();
const R = [];
const log = (uc, ok, msg) => { R.push({ uc, ok: !!ok, msg }); console.log(`[${ok ? "PASS" : "FAIL"}] ${uc}: ${msg}`); };
async function tab(l) { return c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a,nav a')].find(x=>x.innerText.includes(${JSON.stringify(l)}));if(a){a.click();return true}return false`); }
async function api(path) { return c.evaluate(`const r=await fetch('/api${path}',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return await r.json();`); }
await c.navigate(BASE + "/?t=" + Date.now()); await sleep(1200);
if (await c.evaluate(`return !localStorage.getItem('scanops_token')`)) {
  await c.evaluate(`const setN=(el,v)=>{const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};const ins=[...document.querySelectorAll('input')];setN(ins.find(i=>i.type!=='password'),'admin');setN(ins.find(i=>i.type==='password'),${JSON.stringify(PW)});[...document.querySelectorAll('button')].find(b=>/접속|로그인/.test(b.innerText)).click();return true;`);
  await sleep(1800);
}

// UC8: 부서통보 — dept 선택 → 통보문 생성 → 통보 기록
await tab("부서통보"); await sleep(1200);
await c.evaluate(`const s=[...document.querySelectorAll('.main select')].find(s=>[...s.options].some(o=>/인프라운영팀/.test(o.value)));const d=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;d.call(s,'인프라운영팀');s.dispatchEvent(new Event('change',{bubbles:true}));return true;`);
await sleep(1800);
const body = await c.evaluate(`const t=document.querySelector('.main textarea,.main pre');return t?(t.value||t.innerText):''`);
await c.evaluate(`const b=[...document.querySelectorAll('.main button')].find(x=>x.innerText.includes('통보 기록'));if(b)b.click();return true;`);
await sleep(1500);
const hist = await api("/notifications");
log("UC8 부서통보", body.length > 10 && hist.length >= 1, `통보문 ${body.length}자, 기록 ${hist.length}건 (dept=${hist[0]?.dept})`);
await c.screenshot(`${SHOT}/uc8_notify.png`);

// UC9: 내보내기 — 감사리포트 xlsx / 발견 CSV(BOM) / 히트맵 xlsx (in-page fetch, byte-check)
const exp = await c.evaluate(`
  const H={Authorization:'Bearer '+localStorage.getItem('scanops_token')};
  const a=new Uint8Array(await (await fetch('/api/reports/audit',{headers:H})).arrayBuffer());
  const csv=new Uint8Array(await (await fetch('/api/findings/export?cols=host_ip,port,service,risk_level,dept,status&fmt=csv',{headers:H})).arrayBuffer());
  const h=new Uint8Array(await (await fetch('/api/heatmap/report',{headers:H})).arrayBuffer());
  return {auditPK:a[0]===80&&a[1]===75,aLen:a.length,csvBOM:csv[0]===239&&csv[1]===187&&csv[2]===191,cLen:csv.length,heatPK:h[0]===80&&h[1]===75,hLen:h.length};
`);
log("UC9 내보내기", exp.auditPK && exp.csvBOM && exp.heatPK, `감사xlsx=${exp.auditPK}(${exp.aLen}B) CSV BOM=${exp.csvBOM}(${exp.cLen}B) 히트맵xlsx=${exp.heatPK}(${exp.hLen}B)`);

// UC10: 사용자관리 — auditor 생성 + 비밀번호 재설정
await tab("사용자"); await sleep(1000);
await c.evaluate(`
  const di=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
  const ds=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;
  const id=document.querySelector('.main input[placeholder*="아이디"]');di.call(id,'auditor1');id.dispatchEvent(new Event('input',{bubbles:true}));
  const nm=document.querySelector('.main input[placeholder*="이름"]');di.call(nm,'감사담당');nm.dispatchEvent(new Event('input',{bubbles:true}));
  const pw=document.querySelector('.main input[type=password]');di.call(pw,'auditorPass123');pw.dispatchEvent(new Event('input',{bubbles:true}));
  const role=[...document.querySelectorAll('.main select')].find(s=>[...s.options].some(o=>o.value==='auditor'));ds.call(role,'auditor');role.dispatchEvent(new Event('change',{bubbles:true}));
  await new Promise(r=>setTimeout(r,200));
  [...document.querySelectorAll('.main button')].find(b=>b.innerText.trim()==='생성').click();
  return true;
`);
await sleep(1500);
const users = await api("/users");
const aud = (users || []).find?.(u => u.username === "auditor1");
log("UC10 사용자관리", !!aud && aud.role === "auditor", `사용자 ${users?.length}명, auditor1=${!!aud} role=${aud?.role}`);
await c.screenshot(`${SHOT}/uc10_users.png`);

// UC11: 이력 타임라인
await tab("이력"); await sleep(1200);
await c.evaluate(`const b=[...document.querySelectorAll('.main button')].find(x=>x.innerText.trim()==='적용');if(b)b.click();return true;`);
await sleep(1500);
const evRows = await c.evaluate(`return document.querySelectorAll('.main table tbody tr,.main li,.main .ev').length;`);
const ev = await api("/events?limit=500");
log("UC11 이력타임라인", (ev.total || ev.items?.length || 0) > 300, `이력 UI행=${evRows}, API total=${ev.total}`);
await c.screenshot(`${SHOT}/uc11_history.png`);

// UC12: 감사로그 (admin)
const audit = await api("/audit?limit=500");
const acts = {};
(audit || []).forEach(a => acts[a.action] = (acts[a.action] || 0) + 1);
log("UC12 감사로그", (audit?.length || 0) >= 3 && acts.LOGIN && acts.SCAN_IMPORT && acts.RULE_CREATE, `${audit?.length}건: ${JSON.stringify(acts)}`);

// UC13: 히트맵
await tab("히트맵"); await sleep(1800);
const heat = await api("/heatmap");
const hRows = await c.evaluate(`return document.querySelectorAll('.main table tbody tr').length;`);
log("UC13 히트맵", hRows > 50 && (heat.rows?.length || heat.summary), `UI행=${hRows}, phases=${heat.phases?.length}, rows=${heat.rows?.length}`);
await c.screenshot(`${SHOT}/uc13_heatmap.png`);

console.log("\nPASS:", R.filter(r => r.ok).length, "/", R.length);
console.log("exceptions:", c.exceptions.length, "| console errors:", c.consoleMsgs.filter(m => m.type === "error").length, JSON.stringify(c.consoleMsgs.filter(m => m.type === "error").slice(0, 3)));
console.log(JSON.stringify(R));
c.close(); process.exit(R.some(r => !r.ok) ? 1 : 0);

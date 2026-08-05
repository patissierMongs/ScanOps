// UC5 findings filter/search, UC6 finding lifecycle edit (drawer), UC7 risk rules.
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
async function ensureLogin(c) {
  await c.navigate(BASE + "/?t=" + Date.now()); await sleep(1200);
  const need = await c.evaluate(`return !localStorage.getItem('scanops_token')`);
  if (need) {
    await c.evaluate(`
      const setN=(el,v)=>{const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};
      const ins=[...document.querySelectorAll('input')];
      setN(ins.find(i=>i.type!=='password'),'admin'); setN(ins.find(i=>i.type==='password'),${JSON.stringify(PW)});
      [...document.querySelectorAll('button')].find(b=>/접속|로그인/.test(b.innerText)).click(); return true;`);
    await sleep(1800);
  }
}
const SHOT = process.env.SCANOPS_SHOTS || join(DIR, "shots"); mkdirSync(SHOT, { recursive: true });
const c = await connect();
const R = [];
const log = (uc, ok, msg) => { R.push({ uc, ok: !!ok, msg }); console.log(`[${ok ? "PASS" : "FAIL"}] ${uc}: ${msg}`); };
async function tab(l) { return c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a,nav a')].find(x=>x.innerText.includes(${JSON.stringify(l)}));if(a){a.click();return true}return false`); }
async function api(path) { return c.evaluate(`const r=await fetch('/api${path}',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return await r.json();`); }

await ensureLogin(c);

// UC5: filter risk=high (verify UI rows == API) + server search q
await tab("발견 관리"); await sleep(1200);
const highApi = (await api("/findings?state=open&risk=high")).length;
await c.evaluate(`const s=[...document.querySelectorAll('.main select')].find(s=>[...s.options].some(o=>o.value==='high'));const d=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;d.call(s,'high');s.dispatchEvent(new Event('change',{bubbles:true}));return true;`);
await sleep(1200);
const highRows = await c.evaluate(`return document.querySelectorAll('.main table tbody tr').length;`);
// reset risk, then server search "telnet"
await c.evaluate(`const s=[...document.querySelectorAll('.main select')].find(s=>[...s.options].some(o=>o.value==='high'));const d=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;d.call(s,'');s.dispatchEvent(new Event('change',{bubbles:true}));return true;`);
await sleep(1000);
await c.evaluate(`const s=document.querySelector('.main input[placeholder*="검색"]');const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(s,'telnet');s.dispatchEvent(new Event('input',{bubbles:true}));return true;`);
await sleep(2500); // debounce + refetch
const telnetRows = await c.evaluate(`return document.querySelectorAll('.main table tbody tr').length;`);
await c.evaluate(`const s=document.querySelector('.main input[placeholder*="검색"]');const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(s,'');s.dispatchEvent(new Event('input',{bubbles:true}));return true;`);
await sleep(1500);
log("UC5 발견필터/검색", highRows === highApi && telnetRows > 0 && telnetRows < 60, `risk=high UI=${highRows}/API=${highApi}; 검색"telnet"→${telnetRows}행`);
await c.screenshot(`${SHOT}/uc5_findings.png`);

// UC6: open drawer by clicking a data <td>, edit status->처리중 + deadline, save
const opened = await c.evaluate(`
  const tds=[...document.querySelectorAll('.main table tbody tr td')];
  // click a middle data cell (index 3) of the first row to trigger openDrawer
  const cell=[...document.querySelectorAll('.main table tbody tr')][0]?.querySelectorAll('td')[3];
  if(cell) cell.click();
  await new Promise(r=>setTimeout(r,1200));
  return !!document.querySelector('.drawer');
`);
await c.screenshot(`${SHOT}/uc6a_drawer.png`);
let edit = { opened };
if (opened) {
  edit = await c.evaluate(`
    const dr=document.querySelector('.drawer');
    const st=[...dr.querySelectorAll('select')].find(s=>[...s.options].some(o=>o.value==='처리중'));
    const ds=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set; ds.call(st,'처리중'); st.dispatchEvent(new Event('change',{bubbles:true}));
    await new Promise(r=>setTimeout(r,200));
    const dl=dr.querySelector('input[type=date]');
    const di=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set; di.call(dl,'2026-08-15'); dl.dispatchEvent(new Event('input',{bubbles:true}));
    await new Promise(r=>setTimeout(r,200));
    const note=[...dr.querySelectorAll('input')].find(i=>i.type==='text'||i.type==='');
    if(note){di.call(note,'조치 진행중 — 방화벽 정책 검토');note.dispatchEvent(new Event('input',{bubbles:true}));}
    await new Promise(r=>setTimeout(r,200));
    const sv=[...dr.querySelectorAll('button')].find(b=>b.innerText.trim()==='저장');
    if(sv) sv.click();
    await new Promise(r=>setTimeout(r,1200));
    return {opened:true, hadStatus:!!st, hadDeadline:!!dl, hadSave:!!sv};
  `);
}
await sleep(800);
const procList = await api("/findings?state=open&status=처리중");
const proc = procList.length;
// verify events logged for that finding
let evOk = false;
if (proc >= 1) { const ev = await api(`/findings/${procList[0].id}/events`); evOk = ev.some(e => e.type === "STATUS_CHANGE") && ev.some(e => e.type === "DEADLINE"); }
log("UC6 발견운영(상태/마감/이력)", edit.opened && proc >= 1 && evOk, `드로어=${edit.opened}, 처리중=${proc}, STATUS_CHANGE+DEADLINE 이벤트=${evOk}`);
await c.screenshot(`${SHOT}/uc6b_after.png`);

// UC7: add banned_service telnet rule -> reclassify to banned
await tab("규칙"); await sleep(1000);
const banBefore = (await api("/findings?state=open&risk=banned")).length;
await c.evaluate(`
  const di=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
  const ds=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set;
  const kind=[...document.querySelectorAll('.main select')].find(s=>[...s.options].some(o=>o.value==='banned_service')); ds.call(kind,'banned_service'); kind.dispatchEvent(new Event('change',{bubbles:true}));
  await new Promise(r=>setTimeout(r,200));
  const svc=document.querySelector('.main input[placeholder*="telnet"],.main input[placeholder*="서비스"]'); di.call(svc,'telnet'); svc.dispatchEvent(new Event('input',{bubbles:true}));
  const note=document.querySelector('.main input[placeholder*="비고"],.main input[placeholder*="근거"]'); if(note){di.call(note,'평문 원격접속 금지(KISA)');note.dispatchEvent(new Event('input',{bubbles:true}));}
  await new Promise(r=>setTimeout(r,200));
  [...document.querySelectorAll('.main button')].find(b=>b.innerText.trim()==='추가').click();
  return true;
`);
await sleep(2500);
const banAfter = (await api("/findings?state=open&risk=banned")).length;
const rules = await api("/rules");
log("UC7 위험규칙 재분류", banAfter > banBefore && banAfter >= 20, `telnet 금지규칙 → banned ${banBefore}→${banAfter}, 규칙 ${rules.length}건 match=${rules[0]?.match_count}`);
await c.screenshot(`${SHOT}/uc7_rules.png`);

console.log("PASS:", R.filter(r => r.ok).length, "/", R.length);
console.log("exceptions:", c.exceptions.length, "| console errors:", c.consoleMsgs.filter(m => m.type === "error").length);
console.log(JSON.stringify(R));
c.close(); process.exit(R.some(r => !r.ok) ? 1 : 0);

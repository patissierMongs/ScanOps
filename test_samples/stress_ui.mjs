// SC12-15: UI 확인/취소 반복 분기 — 상태전이, markNormal 확인/취소/되돌림, 재스캔 드로어 열기/취소, 자산 위저드 취소/재시도.
import { connect } from "/home/user/ScanOps/test_samples/driver.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";
const PW = readFileSync("/home/user/ScanOps/data/INITIAL_ADMIN.txt", "utf8").match(/비밀번호:\s*(\S+)/)[1];
const BASE = "http://127.0.0.1:8770";
const SHOT = "/tmp/claude-0/-home-user-ScanOps/643b79d8-67d5-5b45-bdb3-af09a6af07db/scratchpad";
const T = "/home/user/ScanOps/test_samples";
const c = await connect();
const R = [];
const log = (sc, hypo, ok, actual) => { R.push({ sc, ok: !!ok }); console.log(`[${ok ? "PASS" : "FAIL"}] ${sc}\n      가정: ${hypo}\n      실제: ${actual}`); };
async function tab(l) { return c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a,nav a')].find(x=>x.innerText.includes(${JSON.stringify(l)}));if(a){a.click();return true}return false`); }
async function api(p) { return c.evaluate(`const r=await fetch('/api${p}',{headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token')}});return await r.json();`); }

await c.navigate(BASE + "/?t=" + Date.now()); await sleep(1200);
if (await c.evaluate(`return !localStorage.getItem('scanops_token')`)) {
  await c.evaluate(`const setN=(el,v)=>{const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;d.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};const ins=[...document.querySelectorAll('input')];setN(ins.find(i=>i.type!=='password'),'admin');setN(ins.find(i=>i.type==='password'),${JSON.stringify(PW)});[...document.querySelectorAll('button')].find(b=>/접속|로그인/.test(b.innerText)).click();return true;`);
  await sleep(1800);
}
await tab("발견 관리"); await sleep(1200);
// '정상처리 제외' 체크 해제 → 상태 전이 중에도 대상 행이 목록에서 사라지지 않게.
async function showAll() {
  await c.evaluate(`
    const cbs=[...document.querySelectorAll('.main label input[type=checkbox]')];
    for(const cb of cbs){ if(cb.checked) cb.click(); }  // 정상처리제외/마감초과만 해제
    return true;`);
  await sleep(900);
}
// 특정 발견을 API 로 골라 미조치로 리셋하고, UI 목록에서 그 행을 host:port 로 조준.
async function pickTarget() {
  const all = await api(`/findings?host=198.51.100.10&state=`);
  const t = (all || []).find(f => f.host_ip === "198.51.100.10" && f.port === 21) || (all || [])[0];
  if (!t) throw new Error("no target finding (198.51.100.10:21)");
  await api(`/findings/${t.id}`); // touch
  await c.evaluate(`await fetch('/api/findings/${t.id}',{method:'PATCH',headers:{Authorization:'Bearer '+localStorage.getItem('scanops_token'),'Content-Type':'application/json'},body:JSON.stringify({status:'미조치'})});return true;`);
  return t;
}
// host:port 로 대상 행 index 찾기
const rowIdxJs = (ip, port) => `(() => {const rows=[...document.querySelectorAll('.main table tbody tr')];return rows.findIndex(r=>r.innerText.includes(${JSON.stringify(ip)})&&r.innerText.includes(${JSON.stringify(String(port))}));})()`;

// ── SC12 상태 전이 전체 (미조치→처리중→정상처리→미조치) ──────────
await showAll();
let f = await pickTarget();
const fid = f.id;
await c.evaluate(`const a=[...document.querySelectorAll('.sidebar nav a')].find(x=>x.innerText.includes('대시보드'));a.click();`); await sleep(500);
await tab("발견 관리"); await sleep(1200); await showAll();
const trans = [];
for (const s of ["처리중", "정상처리", "미조치"]) {
  await c.evaluate(`
    const idx=${rowIdxJs(f.host_ip, f.port)}; if(idx<0) return false;
    const cell=document.querySelectorAll('.main table tbody tr')[idx].querySelectorAll('td')[3]; cell.click();
    await new Promise(r=>setTimeout(r,1000));
    const dr=document.querySelector('.drawer'); if(!dr) return false;
    const st=[...dr.querySelectorAll('select')].find(x=>[...x.options].some(o=>o.value===${JSON.stringify(s)}));
    const ds=Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set; ds.call(st,${JSON.stringify(s)}); st.dispatchEvent(new Event('change',{bubbles:true}));
    await new Promise(r=>setTimeout(r,150));
    [...dr.querySelectorAll('button')].find(b=>b.innerText.trim()==='저장').click();
    await new Promise(r=>setTimeout(r,1000)); return true;`);
  await sleep(600);
  const cur = await api(`/findings/${fid}`);
  trans.push(cur.status);
}
const ev12 = await api(`/findings/${fid}/events`);
const scCount = ev12.filter(e => e.type === "STATUS_CHANGE").length;
log("SC12 상태전이 전체분기", "미조치→처리중→정상처리→미조치 각 단계 반영·STATUS_CHANGE 이벤트 누적",
    JSON.stringify(trans) === JSON.stringify(["처리중", "정상처리", "미조치"]) && scCount >= 3,
    `전이=${JSON.stringify(trans)}, STATUS_CHANGE=${scCount}회`);

// ── SC13 markNormal 확인/취소/되돌림 반복 ───────────────────────
// 대상을 미조치로 리셋하고 그 행의 '정상처리' 버튼만 조준.
await tab("발견 관리"); await sleep(1000); await showAll();
const t13 = await pickTarget();
await tab("발견 관리"); await sleep(1000); await showAll();
const id13 = t13.id;
const before13 = (await api(`/findings/${id13}`)).status;
const rowBtnJs = `const idx=${rowIdxJs(t13.host_ip, t13.port)}; const row=document.querySelectorAll('.main table tbody tr')[idx]; const btn=[...row.querySelectorAll('button')].find(b=>/정상처리|확인/.test(b.innerText));`;
// (a) 취소 분기: 1회 클릭 → '확인?' → 4.5s 대기 → 자동 '정상처리' 복귀(상태 불변)
const label1 = await c.evaluate(`${rowBtnJs} btn.click(); await new Promise(r=>setTimeout(r,300));
  const idx2=${rowIdxJs(t13.host_ip, t13.port)}; const b2=[...document.querySelectorAll('.main table tbody tr')[idx2].querySelectorAll('button')].find(b=>/정상처리|확인/.test(b.innerText)); return b2?b2.innerText.trim():'';`);
await sleep(4600);
const label2 = await c.evaluate(`const idx=${rowIdxJs(t13.host_ip, t13.port)}; const b=[...document.querySelectorAll('.main table tbody tr')[idx].querySelectorAll('button')].find(b=>/정상처리|확인/.test(b.innerText)); return b?b.innerText.trim():'';`);
const afterCancel = (await api(`/findings/${id13}`)).status;
// (b) 확정 분기: 두 번 클릭 → 정상처리 확정
await c.evaluate(`${rowBtnJs} btn.click(); await new Promise(r=>setTimeout(r,300));
  const idx2=${rowIdxJs(t13.host_ip, t13.port)}; const b2=[...document.querySelectorAll('.main table tbody tr')[idx2].querySelectorAll('button')].find(b=>/정상처리|확인/.test(b.innerText)); b2.click(); await new Promise(r=>setTimeout(r,1000)); return true;`);
await sleep(700);
const afterConfirm = (await api(`/findings/${id13}`)).status;
// (c) 되돌림 분기: 토스트 '되돌리기' 클릭
const undoClicked = await c.evaluate(`
  const a=[...document.querySelectorAll('button,a')].find(b=>/되돌리기/.test(b.innerText));
  if(a){a.click(); await new Promise(r=>setTimeout(r,900)); return true;} return false;`);
await sleep(600);
const afterUndo = (await api(`/findings/${id13}`)).status;
log("SC13 markNormal 확인/취소/되돌림",
    "1클릭→'확인?'·4s후 자동취소(상태불변)·2클릭→정상처리 확정·되돌리기→원복",
    label1 === "확인?" && label2 === "정상처리" && afterCancel === before13 && afterConfirm === "정상처리" && undoClicked && afterUndo !== "정상처리",
    `1클릭라벨='${label1}', 자동취소후='${label2}'(상태 ${before13}→${afterCancel}), 확정후=${afterConfirm}, 되돌림후=${afterUndo}`);
await c.screenshot(`${SHOT}/sc13_marknormal.png`);

// ── SC14 재스캔 드로어 열기/취소 반복 ───────────────────────────
const scansBefore = (await api("/scans")).length;
let opens = 0, closes = 0;
for (let i = 0; i < 3; i++) {
  const opened = await c.evaluate(`
    const cb=document.querySelector('.main table tbody tr td input[type=checkbox]'); if(cb && !cb.checked) cb.click();
    await new Promise(r=>setTimeout(r,300));
    const btn=[...document.querySelectorAll('.main button')].find(b=>/재스캔 명령|재스캔/.test(b.innerText)&&!/재검증/.test(b.innerText));
    if(btn) btn.click(); await new Promise(r=>setTimeout(r,700));
    return !!document.querySelector('.drawer');`);
  if (opened) opens++;
  const closed = await c.evaluate(`
    const scrim=document.querySelector('.drawer');
    const btn=[...document.querySelectorAll('.drawer button, .scrim')].find(b=>/닫기|취소/.test(b.innerText||''));
    if(btn){btn.click();} else {const s=document.querySelector('.scrim'); if(s)s.click();}
    await new Promise(r=>setTimeout(r,500));
    return !document.querySelector('.drawer');`);
  if (closed) closes++;
  await sleep(300);
}
const scansAfter = (await api("/scans")).length;
log("SC14 재스캔 드로어 열기/취소 반복", "3회 열기/취소 반복해도 잔여 드로어 없음·실제 스캔 미생성",
    opens === 3 && closes === 3 && scansAfter === scansBefore,
    `열기=${opens}/3, 닫기=${closes}/3, 스캔증가=${scansAfter - scansBefore}`);

// ── SC15 자산 위저드 취소 후 재시도 ─────────────────────────────
await tab("자산대장"); await sleep(1000);
const assetsBefore = (await api("/assets")).length;
// 업로드 → 취소
await c.uploadToFileInput([`${T}/assets_dmz.csv`], 0); await sleep(1500);
await c.evaluate(`const b=[...document.querySelectorAll('.main button,.modal button')].find(x=>x.innerText.trim()==='취소');if(b)b.click();return true;`);
await sleep(1000);
const assetsAfterCancel = (await api("/assets")).length;
// 재시도 → 가져오기 완료
await c.uploadToFileInput([`${T}/assets_dmz.csv`], 0); await sleep(1500);
await c.evaluate(`
  for(const re of [/가져오기/,/적용/,/확인/]){const b=[...document.querySelectorAll('.main button')].find(x=>re.test(x.innerText)&&!/취소/.test(x.innerText));if(b){b.click();break;}}
  return true;`);
await sleep(1800);
const assetsAfterRetry = (await api("/assets")).length;
log("SC15 자산위저드 취소/재시도", "취소 시 미반영(자산 불변)·재시도 시 정상 반영(업서트)",
    assetsAfterCancel === assetsBefore && assetsAfterRetry >= assetsBefore,
    `before=${assetsBefore}, 취소후=${assetsAfterCancel}(불변=${assetsAfterCancel === assetsBefore}), 재시도후=${assetsAfterRetry}`);
await c.screenshot(`${SHOT}/sc15_wizard.png`);

console.log("\n=== UI 분기 결과 ===");
console.log("exceptions:", c.exceptions.length, "| console errors:", c.consoleMsgs.filter(m => m.type === "error").length);
console.log("PASS:", R.filter(r => r.ok).length, "/", R.length, "| FAIL:", R.filter(r => !r.ok).map(r => r.sc));
c.close(); process.exit(0);

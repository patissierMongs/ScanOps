// 구분자 입력 버그 수정 검증 — SAMPLE1.xlsx 를 CDP 로 업로드, 담당자 칸 분리(owner=부분2).
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const SAMPLE = "C:\\Users\\upica\\OneDrive\\Documents\\SAMPLE1.xlsx";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.send("DOM.enable");
await c.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1200, deviceScaleFactor: 1.4, mobile: false });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);
await c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes("자산대장"))?.click(); return true;`);
await sleep(700);

// 파일 인풋에 CDP 로 SAMPLE1 주입
const inp = await c.send("Runtime.evaluate", { expression: "document.querySelector('input[type=file]')", returnByValue: false });
await c.send("DOM.setFileInputFiles", { files: [SAMPLE], objectId: inp.result.objectId });
await sleep(1500); // FileReader + 파싱 + 자동매핑

// 담당자(idx5) → owner, 구분자 "," 입력, 부분2 선택
const res = await c.evaluate(`
  const setV=(el,v)=>{Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(el,v);el.dispatchEvent(new Event('change',{bubbles:true}));};
  const setI=(el,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,v);el.dispatchEvent(new Event('input',{bubbles:true}));};
  const rows=[...document.querySelectorAll('.map-row')];
  const ownerRow=rows.find(r=>r.querySelector('.map-key')?.innerText.includes('담당자'));
  if(!ownerRow) return { error:'no owner row', cols: document.querySelectorAll('.map-row').length };
  setV(ownerRow.querySelector('select'),'5');
  await new Promise(r=>setTimeout(r,200));
  const sep=ownerRow.querySelector('.map-sep');
  setI(sep,',');
  await new Promise(r=>setTimeout(r,200));
  const sepAfter=ownerRow.querySelector('.map-sep').value;   // 버그면 "" 로 되돌아감
  const part=ownerRow.querySelector('.map-part');
  setV(part,'1'); // 부분 2 (0-index 1)
  await new Promise(r=>setTimeout(r,200));
  return { sepAfter, partDisabled: ownerRow.querySelector('.map-part').disabled, preview: document.querySelector('.pre')?.innerText || '' };
`);

await c.screenshot("samples/feat_assets_split.png");
console.log("sep input persists:", JSON.stringify(res.sepAfter), res.sepAfter === "," ? "OK" : "BUG");
console.log("part enabled:", res.partDisabled === false);
console.log("preview:\n" + res.preview);
console.log("errors:", c.consoleMsgs.filter(m=>m.type==='error').length, "exceptions:", c.exceptions.length);
c.close();

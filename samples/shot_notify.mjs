// 강화된 부서통보 — 부서 선택 + 상태/마감 필터 + 템플릿 렌더 미리보기.
import { connect } from "./cdp.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import { readFileSync } from "node:fs";

const TOKEN = readFileSync("samples/.token", "utf8").trim();
const BASE = "http://localhost:8770";
const c = await connect();
await c.send("Network.setCacheDisabled", { cacheDisabled: true });
await c.send("Emulation.setDeviceMetricsOverride", { width: 1200, height: 1300, deviceScaleFactor: 1.4, mobile: false });
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(500);
await c.evaluate(`localStorage.setItem("scanops_token", ${JSON.stringify(TOKEN)}); return true;`);
await c.navigate(BASE + "/?t=" + Date.now());
await sleep(1500);
await c.evaluate(`[...document.querySelectorAll(".sidebar nav a")].find(x=>x.innerText.includes("부서통보"))?.click(); return true;`);
await sleep(700);

// 부서 선택(첫 실제 부서)
const r = await c.evaluate(`
  const setV=(el,v)=>{Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(el,v);el.dispatchEvent(new Event('change',{bubbles:true}));};
  const sel=document.querySelector('.panel select');
  const opts=[...sel.options].map(o=>o.value).filter(Boolean);
  setV(sel, opts[0]||'');
  await new Promise(r=>setTimeout(r,800));
  return { dept: opts[0], preview: document.querySelector('.pre')?.innerText?.slice(0,200) };
`);
await sleep(400);
await c.screenshot("samples/notify_enhanced.png");
console.log("dept:", r.dept);
console.log("preview head:\n" + r.preview);
console.log("errors:", c.consoleMsgs.filter(m=>m.type==='error').length, "exceptions:", c.exceptions.length);
c.close();

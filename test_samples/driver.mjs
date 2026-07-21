// Enhanced CDP driver for ScanOps E2E — Node 22 global WebSocket + fetch.
// Adds file-input upload (DOM.setFileInputFiles) on top of navigate/evaluate/screenshot.
import { setTimeout as sleep } from "node:timers/promises";

const PORT = process.env.CDP_PORT || 9222;

async function getPageTarget() {
  for (let i = 0; i < 40; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      const page = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch (_) {}
    await sleep(250);
  }
  throw new Error("No CDP page target on " + PORT);
}

export async function connect() {
  const target = await getPageTarget();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

  let id = 0;
  const pending = new Map();
  const consoleMsgs = [];
  const exceptions = [];

  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id != null && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    } else if (msg.method === "Runtime.consoleAPICalled") {
      const txt = (msg.params.args || []).map((a) => a.value ?? a.description ?? "").join(" ");
      consoleMsgs.push({ type: msg.params.type, text: txt });
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      exceptions.push(d.exception?.description || d.text || JSON.stringify(d));
    }
  };

  function send(method, params = {}) {
    const mid = ++id;
    return new Promise((resolve, reject) => {
      pending.set(mid, { resolve, reject });
      ws.send(JSON.stringify({ id: mid, method, params }));
    });
  }

  await send("Page.enable");
  await send("Runtime.enable");
  await send("DOM.enable");
  await send("Network.enable");
  await send("Network.setCacheDisabled", { cacheDisabled: true });

  async function navigate(url) {
    await send("Page.navigate", { url });
    await sleep(400);
  }

  async function evaluate(expr) {
    const r = await send("Runtime.evaluate", {
      expression: `(async()=>{ ${expr} })()`,
      awaitPromise: true, returnByValue: true, userGesture: true,
    });
    if (r.exceptionDetails)
      throw new Error("EVAL: " + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result.value;
  }

  // Upload files to the Nth (default 0) input[type=file] on the page.
  async function uploadToFileInput(absPaths, which = 0) {
    const doc = await send("DOM.getDocument", { depth: -1 });
    const q = await send("DOM.querySelectorAll", {
      nodeId: doc.root.nodeId, selector: 'input[type=file]',
    });
    const nodeIds = q.nodeIds || [];
    if (!nodeIds.length) return { ok: false, reason: "no file input" };
    const nodeId = nodeIds[Math.min(which, nodeIds.length - 1)];
    await send("DOM.setFileInputFiles", { files: absPaths, nodeId });
    return { ok: true, count: absPaths.length, inputs: nodeIds.length };
  }

  async function screenshot(path) {
    const r = await send("Page.captureScreenshot", { format: "png" });
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, Buffer.from(r.data, "base64"));
    return path;
  }

  return { send, evaluate, navigate, uploadToFileInput, screenshot, consoleMsgs, exceptions, close: () => ws.close() };
}

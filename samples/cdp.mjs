// Minimal CDP driver using Node 22 global WebSocket + fetch.
// Connects to a Chrome launched with --remote-debugging-port, navigates, and
// exposes evaluate() to run JS in the page (awaiting promises).
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = process.env.CDP_PORT || 9222;

async function getPageTarget() {
  for (let i = 0; i < 40; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      const page = list.find(t => t.type === 'page' && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch (_) {}
    await sleep(250);
  }
  throw new Error('No CDP page target found — is Chrome up on port ' + PORT + '?');
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
    } else if (msg.method === 'Runtime.consoleAPICalled') {
      const txt = (msg.params.args || []).map(a => a.value ?? a.description ?? a.unserializableValue ?? '').join(' ');
      consoleMsgs.push({ type: msg.params.type, text: txt });
    } else if (msg.method === 'Runtime.exceptionThrown') {
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

  await send('Page.enable');
  await send('Runtime.enable');

  async function navigate(url) {
    await send('Page.navigate', { url });
    // wait for load
    await sleep(300);
  }

  // Evaluate an expression, awaiting promises, returning the JSON value.
  async function evaluate(expr) {
    const r = await send('Runtime.evaluate', {
      expression: `(async()=>{ ${expr} })()`,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    });
    if (r.exceptionDetails) {
      throw new Error('EVAL ERROR: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    }
    return r.result.value;
  }

  async function screenshot(path) {
    const r = await send('Page.captureScreenshot', { format: 'png' });
    const { writeFile } = await import('node:fs/promises');
    await writeFile(path, Buffer.from(r.data, 'base64'));
    return path;
  }

  return { send, evaluate, navigate, screenshot, consoleMsgs, exceptions, close: () => ws.close() };
}

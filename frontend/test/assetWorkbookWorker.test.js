import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { Worker as NodeWorker } from "node:worker_threads";
import * as XLSX from "xlsx";

import { createAssetWorkbookSession } from "../src/lib/assetWorkbookSession.js";
import {
  ASSET_WORKBOOK_TIMEOUT_MS,
  createAssetWorkbookParser,
  isCurrentAssetWorkbookSession,
} from "../src/lib/assetWorkbookWorkerClient.js";


const workbookBytes = (bookType = "xlsx") => {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
    ["IP", "부서"], ["10.0.0.1", "보안팀"],
  ]), "assets");
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
    ["IP", "부서"], ["10.0.0.2", "운영팀"],
  ]), "secondary");
  return XLSX.write(wb, { type: "array", bookType });
};


test("Assets routes workbook parsing through the production worker client", () => {
  const assets = readFileSync(new URL("../src/views/Assets.jsx", import.meta.url), "utf8");
  const client = readFileSync(new URL("../src/lib/assetWorkbookWorkerClient.js", import.meta.url), "utf8");
  assert.match(assets, /createAssetWorkbookParser\(\)/);
  assert.match(assets, /await parser\.open\(reader\.result\)/);
  assert.doesNotMatch(assets, /\breadWorkbook\b/);
  assert.match(assets, /function cancelImport\(\)[\s\S]*?parserRef\.current\?\.terminate\(\)[\s\S]*?setImp\(null\)/);
  assert.match(assets, /onClick=\{cancelImport\}>취소<\/button>/);
  assert.match(client, /new Worker\(\s*new URL\("\.\/assetWorkbook\.worker\.js", import\.meta\.url\)/);
  assert.match(client, /worker\.terminate\(\)/);
  assert.equal(ASSET_WORKBOOK_TIMEOUT_MS, 10_000);
});


test("new file selection clears stale workbook state before validation can fail", () => {
  const assets = readFileSync(new URL("../src/views/Assets.jsx", import.meta.url), "utf8");
  const start = assets.indexOf("function onFile(e)");
  const end = assets.indexOf("function setHeaderRow", start);
  const onFile = assets.slice(start, end);
  const order = [
    "if (!file) return;",
    "const requestId = ++parseRequestRef.current;",
    "parserRef.current?.terminate();",
    "parserRef.current = null;",
    "setImp(null);",
    'setPresetId("");',
    "if (file.size > MAX_ASSET_FILE_BYTES)",
  ].map((needle) => onFile.indexOf(needle));

  assert.ok(start >= 0 && end > start, "onFile source must be present");
  assert.ok(order.every((index) => index >= 0), "every stale-session reset must be present");
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
});


test("bulk completion owns only the workbook session captured at request time", () => {
  const parserA = {};
  const parserB = {};
  const captured = { requestId: 7, parser: parserA };

  assert.equal(isCurrentAssetWorkbookSession(captured, 7, parserA), true);
  assert.equal(isCurrentAssetWorkbookSession(captured, 8, parserA), false);
  assert.equal(isCurrentAssetWorkbookSession(captured, 7, parserB), false);
  assert.equal(isCurrentAssetWorkbookSession(null, 7, parserA), false);

  const assets = readFileSync(new URL("../src/views/Assets.jsx", import.meta.url), "utf8");
  assert.match(assets, /const importSession = \{ requestId: parseRequestRef\.current, parser: parserRef\.current \}/);
  assert.match(
    assets,
    /isCurrentAssetWorkbookSession\(importSession, parseRequestRef\.current, parserRef\.current\)\) cancelImport\(\)/,
  );
});


test("worker session preserves XLSX, legacy XLS, CSV, and sheet selection", async (t) => {
  const cases = [
    ["xlsx", workbookBytes("xlsx"), "10.0.0.1"],
    ["xls", workbookBytes("biff8"), "10.0.0.1"],
    ["csv", new TextEncoder().encode("IP,부서\r\n10.0.0.3,개발팀\r\n"), "10.0.0.3"],
  ];

  for (const [name, bytes, expectedIp] of cases) {
    await t.test(name, () => {
      const session = createAssetWorkbookSession();
      const parsed = session.open(bytes);
      assert.equal(parsed.aoa[1][0], expectedIp);
      assert.equal(parsed.sheet, parsed.sheetNames[0]);
      if (name !== "csv") {
        const secondary = session.selectSheet("secondary");
        assert.equal(secondary.aoa[1][0], "10.0.0.2");
      }
    });
  }
});


class ReplyWorker {
  constructor() {
    this.terminated = false;
    this.messages = [];
  }

  postMessage(message, transfer) {
    this.messages.push({ message, transfer });
    queueMicrotask(() => this.onmessage?.({
      data: {
        id: message.id,
        ok: true,
        result: message.type === "open"
          ? { sheetNames: ["assets"], sheet: "assets", aoa: [["IP"]], mergeCount: 0 }
          : { sheetNames: ["assets", "other"], sheet: message.sheet, aoa: [["IP"]], mergeCount: 0 },
      },
    }));
  }

  terminate() {
    this.terminated = true;
  }
}


test("worker client transfers the file and keeps the session for sheet changes", async () => {
  const worker = new ReplyWorker();
  const parser = createAssetWorkbookParser({ workerFactory: () => worker, timeoutMs: 1000 });
  const buffer = new ArrayBuffer(16);

  const opened = await parser.open(buffer);
  assert.equal(opened.sheet, "assets");
  assert.equal(worker.messages[0].transfer[0], buffer);

  const selected = await parser.selectSheet("other");
  assert.equal(selected.sheet, "other");
  assert.deepEqual(worker.messages[1].transfer, []);

  parser.terminate();
  assert.equal(worker.terminated, true);
});


class NodeWorkerAdapter {
  constructor(worker) {
    this.worker = worker;
    this.terminated = false;
    this.parsing = false;
    this.termination = null;
    worker.on("message", (data) => {
      if (data?.probe === "parsing") {
        this.parsing = true;
        return;
      }
      this.onmessage?.({ data });
    });
    worker.on("error", (error) => this.onerror?.({ message: error.message }));
  }

  postMessage(message, transfer) {
    this.worker.postMessage(message, transfer);
  }

  terminate() {
    this.terminated = true;
    this.termination = this.worker.terminate();
    return this.termination;
  }
}


test("worker rejects hostile wide CSV through grid preflight", async (t) => {
  const sessionUrl = new URL("../src/lib/assetWorkbookSession.js", import.meta.url).href;
  const source = `
    const { parentPort } = require("node:worker_threads");
    import(${JSON.stringify(sessionUrl)}).then(({ createAssetWorkbookSession, handleAssetWorkbookRequest }) => {
      const session = createAssetWorkbookSession();
      parentPort.on("message", (request) => setImmediate(() => {
        parentPort.postMessage({ probe: "parsing", id: request.id });
        parentPort.postMessage(handleAssetWorkbookRequest(session, request));
      }));
      parentPort.postMessage({ probe: "ready" });
    });
  `;
  const worker = new NodeWorker(source, { eval: true });
  t.after(() => worker.terminate());
  const [ready] = await once(worker, "message");
  assert.equal(ready.probe, "ready");

  const adapter = new NodeWorkerAdapter(worker);
  const parser = createAssetWorkbookParser({ workerFactory: () => adapter, timeoutMs: 1000 });
  const hostileCsv = new TextEncoder().encode(`${"a,".repeat(513)}a\r\n`);

  await assert.rejects(parser.open(hostileCsv), /처리 한도/);
  assert.equal(adapter.parsing, true, "the real parser must start processing the hostile payload");
  assert.equal(adapter.terminated, false, "a validation error must not kill the reusable worker session");
  parser.terminate();
  assert.equal(adapter.terminated, true);
  await adapter.termination;
});


class SilentWorker {
  constructor() {
    this.messages = [];
    this.terminateCalls = 0;
  }

  postMessage(message, transfer) {
    this.messages.push({ message, transfer });
  }

  terminate() {
    this.terminateCalls += 1;
  }
}


test("nonresponsive worker is terminated at the hard deadline", async () => {
  const worker = new SilentWorker();
  const parser = createAssetWorkbookParser({ workerFactory: () => worker, timeoutMs: 25 });

  await assert.rejects(parser.open(new ArrayBuffer(8)), /파싱 시간 제한\(25ms\)/);
  assert.equal(worker.messages.length, 1);
  assert.equal(worker.terminateCalls, 1);
  await assert.rejects(parser.selectSheet("other"), /파서가 종료되었습니다/);
  assert.equal(worker.terminateCalls, 1);
});

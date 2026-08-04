import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { cellValue, PRESETS, primaryServiceIdentity } from "../src/lib/columns.js";
import { deadlinePatchValue } from "../src/lib/findingPatch.js";
import { scanKind, shouldLoadStages } from "../src/lib/scanStatus.js";
import { toastAnnouncement, toastDuration } from "../src/lib/toast.js";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("successful async work uses one polite atomic toast announcement", async () => {
  const result = await Promise.resolve().then(() => toastAnnouncement(""));
  assert.deepEqual(result, { role: "status", live: "polite" });
  assert.match(source("../src/ui/Toast.jsx"), /aria-atomic="true"/);
});

test("failed async work uses one assertive alert announcement", async () => {
  const result = await Promise.reject(new Error("failed")).catch(() => toastAnnouncement("err"));
  assert.deepEqual(result, { role: "alert", live: "assertive" });
});

test("toast actions remain keyboard buttons long enough to use", () => {
  assert.ok(toastDuration({ action: { label: "되돌리기" } }) >= 6000);
  assert.match(source("../src/ui/Toast.jsx"), /<button[\s\S]*?t\.action\.onClick/);
});

test("service identity keeps raw Server separate from fallback display identity", () => {
  assert.equal(primaryServiceIdentity({ display_identity: "uvicorn", server: "raw", service: "http" }), "uvicorn");
  assert.equal(primaryServiceIdentity({ server: "nginx", product: "Generic HTTP", service: "http" }), "nginx");
  assert.equal(primaryServiceIdentity({ product: "OpenSSH", version: "9.7", service: "ssh" }), "OpenSSH 9.7");
  assert.equal(primaryServiceIdentity({ service: "ssh" }), "ssh");
  assert.equal(cellValue({ display_identity: "nginx", server: "" }, "server"), "");
  assert.ok(PRESETS.find((preset) => preset.id === "p_report").cols.includes("display_identity"));
});

test("clearing a finding deadline sends an explicit null", () => {
  assert.equal(deadlinePatchValue(""), null);
  assert.equal(deadlinePatchValue("2026-07-29"), "2026-07-29T00:00:00");
});

test("scan history distinguishes staged, XML import, and legacy work", () => {
  assert.equal(scanKind({ kind: "staged" }).key, "staged");
  assert.equal(scanKind({ name: "가져오기: result.xml" }).key, "import");
  assert.equal(scanKind({ command: "nmap -sV 127.0.0.1" }).key, "legacy");
});

test("initial scan history hydrates missing staged timelines without probing terminal imports", () => {
  assert.equal(shouldLoadStages({ status: "done", command: "단계스캔(엔진) · TCP 443" }), true);
  assert.equal(shouldLoadStages({ status: "running", command: "nmap -sV 127.0.0.1" }), true);
  assert.equal(shouldLoadStages({ status: "done", name: "가져오기: result.xml" }), false);
  assert.equal(shouldLoadStages({ status: "done", command: "nmap -sV 127.0.0.1" }), false);
  assert.equal(shouldLoadStages({
    status: "done", command: "단계스캔(엔진) · TCP 443", stages_json: [{ stage: "tcp" }],
  }), false);
  assert.match(source("../src/views/Scans.jsx"), /list\.filter\(shouldLoadStages\)/);
});

test("mobile navigation and password dialog retain keyboard contracts", () => {
  const app = source("../src/App.jsx");
  const modal = source("../src/ui/PasswordModal.jsx");
  const css = source("../src/styles.css");
  assert.match(app, /setInert\(sidebar, !navOpen\)/);
  assert.match(app, /setInert\(main, navOpen\)/);
  assert.match(app, /event\.key !== "Tab"/);
  assert.match(app, /aria-current=\{view === n\.k \? "page"/);
  assert.match(app, /onSuccess=\{onLogout\}/);
  assert.match(modal, /role="dialog" aria-modal="true"/);
  assert.match(modal, /onKeyDown=\{onDialogKeyDown\}/);
  assert.match(modal, /shell\.inert = true/);
  assert.match(css, /\.sidebar\.open[^}]*pointer-events: auto/);
  assert.match(css, /\.modal[^}]*z-index: 50/);
});

test("search Enter handlers ignore Korean IME composition", () => {
  for (const file of ["../src/views/Findings.jsx", "../src/views/History.jsx"]) {
    const view = source(file);
    assert.match(view, /nativeEvent\.isComposing \|\| e\.keyCode === 229/);
    assert.match(view, /if \(e\.key === "Enter"\) load\(\)/);
  }
});

test("mobile table panels expose overflowing columns inside the panel", () => {
  const css = source("../src/styles.css");
  const dashboard = source("../src/views/Dashboard.jsx");
  assert.match(css, /\.panel:has\(\.tbl\)\s*\{\s*overflow-x:\s*auto;/);
  assert.match(css, /\.recent-scans-table\s*\{\s*min-width:\s*430px;/);
  assert.match(dashboard, /className="tbl recent-scans-table"/);
});

test("XML import is activated by visible buttons and restores their focus", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /ref=\{fileButtonRef\}[\s\S]*?XML 가져오기/);
  assert.match(scans, /type="file"[^>]*hidden tabIndex=\{-1\}/);
  assert.match(scans, /restore\?\.isConnected[^\n]*restore\.focus\(\)/);
  assert.equal((scans.match(/onCancel=\{restoreImportFocus\}/g) || []).length, 2);
  assert.match(scans, /e\.target\.value = "";\s*const restore = restoreImportFocus\(\)/);
  assert.match(scans, /importFiles\(files, restore\)/);
  assert.match(scans, /restoreFocusTo\?\.isConnected[^\n]*restoreFocusTo\.focus\(\)/);
  assert.doesNotMatch(scans, /<label className="linkbtn"[\s\S]{0,160}type="file"/);
});

test("scan details expose persisted timeline and safe failure fields", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /withPersistedStages/);
  assert.match(scans, /\/scans\/\$\{scan\.id\}\/stages/);
  assert.match(scans, /timeline_available/);
  assert.match(scans, /failure_message/);
  assert.match(scans, /failure_code/);
});

test("heatmap and notification mirrors use display identity with service context", () => {
  const heatmap = source("../src/views/Heatmap.jsx");
  const notifications = source("../src/views/Notifications.jsx");
  assert.match(heatmap, /row\.display_identity, row\.server/);
  assert.match(heatmap, /primaryServiceIdentity\(finding\)/);
  assert.match(notifications, /const identity = primaryServiceIdentity\(f\)/);
  assert.match(notifications, /\(서비스: \$\{f\.service\}\)/);
});

test("Server changes have a localized history label and filter", () => {
  const history = source("../src/views/History.jsx");
  assert.match(history, /SERVER_CHANGED:\s*\{ label: "Server 변경", cls: "medium" \}/);
  assert.match(history, /"SERVER_CHANGED"/);
});

test("finding rescan pins execution to the selected IP and port pairs", () => {
  const findings = source("../src/views/Findings.jsx");
  const request = findings.split("\n").find((line) => line.includes('api("/findings/rescan"'));
  assert.match(request, /finding_ids: ids, options: opt\.options, nse: opt\.nse/);
  assert.doesNotMatch(request, /ports:/);
  assert.match(findings, /fixedTargetPorts/);
  assert.match(findings, /선택 포트만 2-pass 정밀 확인/);
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  assert.match(scanOptions, /선택한 발견의 포트만 재검증하므로 변경할 수 없습니다/);
  assert.match(scanOptions, /!fixedTargetPorts && <div className="scan-actions">/);
  assert.match(scanOptions, /RESCAN_OPTION_KEYS = new Set\(\["version_all", "version_light"\]\)/);
  const fixedPreviewBranch = scanOptions
    .split("{fixedTargetPorts ? (").at(-1)
    .split(") : (")[0];
  assert.match(fixedPreviewBranch, /위에 표시된 발견별 IP:포트 개별 명령/);
  assert.doesNotMatch(fixedPreviewBranch, /실행될 명령어|steps\.map|scan-command/);
});

test("staged scan submits the options used by its UDP preview", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  assert.match(
    scanOptions,
    /: staged \|\| workflow === "manual" \? \[\.\.\.sel\] : \[\]/,
  );
});

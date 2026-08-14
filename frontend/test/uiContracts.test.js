import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  cellValue, currentReason, needsConfirmation, PRESETS, primaryServiceIdentity,
  stateWithEvidence,
} from "../src/lib/columns.js";
import { deadlinePatchValue } from "../src/lib/findingPatch.js";
import { SCAN_STATUS, scanKind, scanNotice, scanStatus, shouldLoadStages } from "../src/lib/scanStatus.js";
import { splitScanTokens } from "../src/lib/scanTargets.js";
import { toastAnnouncement, toastDuration } from "../src/lib/toast.js";
import { matchesFilter, parseNeedle } from "../src/lib/filterText.js";
import { formatImportSummary } from "../src/lib/scanImports.js";
import { matchFocus } from "../src/lib/ruleFocus.js";
import { PAGE_SIZES } from "../src/lib/pageSize.js";

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
  assert.equal(cellValue({ state: "open|filtered" }, "state"), "open|filtered");
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
  // Enter 로 검색하는 화면은 조합 중 Enter(한글 확정)를 검색으로 오인하면 안 된다.
  const view = source("../src/views/History.jsx");
  assert.match(view, /nativeEvent\.isComposing \|\| e\.keyCode === 229/);
  assert.match(view, /if \(e\.key === "Enter"\) load\(\)/);
});

test("findings search debounces on typing without firing mid-composition", () => {
  const view = source("../src/views/Findings.jsx");
  // 입력하는 대로 검색하므로 Enter 는 필요 없지만, 조합 중에는 질의가 나가면 안 된다.
  // 'ㄴ' → '나' → '남' 단계마다 검색하면 엉뚱한 결과가 스쳐 가고 서버도 헛돈다.
  assert.match(view, /onCompositionStart: \(\) => \{ composing\.current = true; \}/);
  assert.match(view, /onCompositionEnd: \(\) => \{ composing\.current = false; setImeTick/);
  assert.match(view, /if \(composing\.current\) return;/);
  assert.match(view, /setTimeout\(\(\) => \{ setPage\(0\); load\(0\); \}, 250\)/);
  // 조합이 끝나면 그때 한 번은 반드시 나가야 한다.
  assert.match(view, /\[queryString\.toString\(\), imeTick, pageSize\]/);
  // 검색창과 컬럼 필터 모두 같은 보호를 받는다.
  assert.ok(view.split("{...imeProps}").length - 1 >= 3, "search + column filters must share the IME guard");
});

test("findings table offers per-column filters, sorting, and a filter reset", () => {
  const view = source("../src/views/Findings.jsx");
  const css = source("../src/styles.css");
  assert.match(view, /className="filter-row"/);
  assert.match(view, /onClick=\{\(\) => toggleSort\(k\)\}/);
  // 오름차순 → 내림차순 → 해제 순환이어야 원래 순서로 돌아올 수 있다.
  assert.match(view, /s\.dir === "asc" \? \{ key, dir: "desc" \} : \{ key: "", dir: "asc" \}/);
  assert.match(view, /필터 제거/);
  assert.match(view, /setMatch\("contains"\)/);
  assert.match(view, /setMatch\("exact"\)/);
  assert.match(css, /\.tbl thead tr\.filter-row/);
});

test("table panels contain overflowing columns at every shell breakpoint", () => {
  const css = source("../src/styles.css");
  const dashboard = source("../src/views/Dashboard.jsx");
  const mobileMedia = css.indexOf("@media (max-width: 760px)");
  const tableOverflow = css.indexOf(".panel:has(.tbl) { overflow-x: auto; }");
  assert.match(css, /\.main\s*\{[^}]*min-width:\s*0;[^}]*overflow:\s*auto;/);
  assert.ok(tableOverflow >= 0 && tableOverflow < mobileMedia,
    "table overflow containment must apply before the mobile-only media query");
  assert.match(css, /\.panel:has\(\.tbl\)\s*\{\s*overflow-x:\s*auto;/);
  assert.match(css, /\.recent-scans-table\s*\{\s*min-width:\s*430px;/);
  assert.match(dashboard, /className="tbl recent-scans-table"/);
});

test("dashboard and scan history share every localized scan status", () => {
  assert.deepEqual(
    Object.fromEntries(Object.keys(SCAN_STATUS).map((status) => [status, scanStatus(status).label])),
    {
      running: "실행 중",
      canceling: "중지 중",
      canceled: "중지됨",
      interrupted: "중단됨(서버 재시작)",
      failed: "실패",
      // nmap 이 끝까지 정상 종료하지 못한 실행 — 결과는 쓰되 닫힘 판정에서 제외된다.
      partial: "부분 완료",
      done: "완료",
    },
  );
  assert.match(source("../src/views/Dashboard.jsx"), /scanStatus\(s\.status\)\.label/);
  assert.match(source("../src/views/Scans.jsx"), /const st = scanStatus\(s\.status\)/);
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

test("standalone folder import sends each preflighted XML/manifest group", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /prepareImportGroups\(fileList\)/);
  assert.match(scans, /runImportGroups\(plan, async \(group\)/);
  assert.match(scans, /uploadMany\("\/scans\/import-bundle", group\.files\)/);
  assert.match(scans, /accept="\.xml,\.manifest\.json"/);
  assert.match(scans, /formatImportSummary\(summary\)/);
  // 라벨은 짧게 두고 'manifest 까지 함께 읽는다'는 설명은 보조 문구로 — 폴더 경로 자체는 남아야 한다.
  assert.match(scans, /폴더째 가져오기/);
  assert.match(scans, /manifest 까지 함께 읽습니다/);
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
  assert.match(history, /import \{ primaryServiceIdentity \} from "\.\.\/lib\/columns\.js"/);
  assert.match(history, /const identity = primaryServiceIdentity\(ev\)/);
  assert.match(history, /\(서비스: \$\{ev\.service\}\)/);
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

test("scan exclusions share one deduplicated token contract across estimate and run modes", () => {
  assert.deepEqual(
    splitScanTokens("10.0.0.1, 10.0.1.0/24\r\n10.0.0.1"),
    ["10.0.0.1", "10.0.1.0/24"],
  );
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /const excludeList = splitScanTokens\(exclude\)/);
  assert.match(scans, /\/scans\/estimate[\s\S]*?exclude: excludeList/);
  assert.match(scans, /const estKey = JSON\.stringify\(\{[^}]*s: staged \}\)/);
  assert.match(scans, /\/scans\/estimate[\s\S]*?batch_size: batchSize, staged/);
  // estimate + staged run + 일반 run + 직접 명령. 직접 명령 모드도 제외를 보내야 한다:
  // 예전에는 이 경로만 제외를 버려서 폼에 입력한 제외가 조용히 사라졌다.
  assert.equal((scans.match(/exclude: excludeList/g) || []).length, 4);
  assert.match(scans, /\/scans\/run-command[\s\S]*?exclude: excludeList/);
  assert.match(scans, /const previewExcludes = est\?\.exclude \?\? excludeList/);
  assert.match(scans, /targets=\{targetList\} excludes=\{previewExcludes\} staged=\{staged\}/);
  assert.match(scans, /setTargets\(""\); setExclude\(""\); setName\(""\)/);
  assert.match(scans, /htmlFor="scan-exclude"/);
  assert.match(scans, /aria-describedby="scan-exclude-help"/);
  assert.match(scans, /<textarea id="scan-exclude"[^>]*rows=\{2\}/);

  const scanOptions = source("../src/ui/ScanOptions.jsx");
  assert.match(scanOptions, /excludes\.length \? \["--exclude", excludes\.join\(","\)\] : \[\]/);
  assert.equal((scanOptions.match(/\.\.\.excludeArgs/g) || []).length, 9);
  assert.match(scanOptions, /if \(selectedScripts\.length\)[^\n]+\n\s*parts\.push\(\.\.\.excludeArgs\)/);
});

test("scan type controls cannot submit connect with SYN or UDP", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  const toggle = scanOptions.slice(
    scanOptions.indexOf("function toggle(k)"),
    scanOptions.indexOf("function toggleNse(k)"),
  );
  const selectionToggle = toggle.slice(toggle.indexOf("const n = new Set(s)"));
  const connect = selectionToggle.slice(
    selectionToggle.indexOf('k === "connect"'),
    selectionToggle.indexOf('k === "udp"'),
  );
  assert.match(connect, /n\.add\("connect"\)/);
  assert.match(connect, /n\.delete\("syn"\)/);
  assert.match(connect, /n\.delete\("udp"\)/);
  assert.match(connect, /n\.delete\("defeat_rst"\)/);
  const udp = selectionToggle.slice(selectionToggle.indexOf('k === "udp"'));
  assert.match(udp, /n\.add\("udp"\)/);
  assert.match(udp, /n\.add\("syn"\)/);
  assert.match(udp, /n\.delete\("connect"\)/);
  assert.match(scanOptions, /const nextSel = normalizeSelections\(p\.options \|\| \[\]\)/);
  assert.match(scanOptions, /next\.has\("connect"\)[\s\S]*?next\.delete\("defeat_rst"\)/);
});

test("port presets and protocol toggles keep staged request combinations valid", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  assert.match(scanOptions, /function tcpOnlyPortSpec\(spec\)[\s\S]*?`T:\$\{tcp \|\| "1-65535"\}`/);

  const toggle = scanOptions.slice(
    scanOptions.indexOf("function toggle(k)"),
    scanOptions.indexOf("function toggleNse(k)"),
  );
  assert.match(toggle, /k === "connect" \|\| \(k === "udp" && sel\.has\("udp"\)\)/);
  assert.match(toggle, /setPorts\(\(current\) => tcpOnlyPortSpec\(current\)\)/);

  const portInput = scanOptions.slice(
    scanOptions.indexOf("const setPortPreset"),
    scanOptions.indexOf("function applyPrecision"),
  );
  assert.match(portInput, /hasExplicitUdpPorts\(spec\)/);
  assert.match(portInput, /n\.add\("syn"\)[\s\S]*?n\.add\("udp"\)[\s\S]*?n\.delete\("connect"\)/);

  const preset = scanOptions.slice(
    scanOptions.indexOf("function applyPreset"),
    scanOptions.indexOf("function savePreset"),
  );
  assert.match(preset, /nextSel\.has\("connect"\)[\s\S]*?nextPorts = tcpOnlyPortSpec\(nextPorts\)/);
  assert.match(preset, /hasExplicitUdpPorts\(nextPorts\)[\s\S]*?nextSel\.add\("udp"\)/);
});

test("scan presets live on the server so the standalone scanner can sync the same file", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  // localStorage 에 남으면 단독 스캐너 동기화 대상에서 빠진다 — 읽기/쓰기 모두 서버 API 로.
  assert.match(scanOptions, /api\("\/scan-presets"\)/);
  assert.doesNotMatch(scanOptions, /localStorage\.setItem\(LEGACY_PRESET_KEY/);

  // 파일 형식의 workflow 어휘는 단독 스캐너 기준(single) — 웹의 manual 과 상호 변환한다.
  assert.match(scanOptions, /const toStoredWorkflow = \(workflow\) => \(workflow === "auto" \? "auto" : "single"\)/);
  assert.match(scanOptions, /const toUiWorkflow = \(workflow\) => \(workflow === "auto" \? "auto" : "manual"\)/);
  assert.match(scanOptions, /setWorkflow\(toUiWorkflow\(p\.workflow\)\)/);
  assert.match(scanOptions, /workflow: toStoredWorkflow\(workflow\)/);
});

test("preset writes touch one name so a stale list cannot erase other people's presets", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  // 목록 전체를 되보내면 이 화면이 목록을 읽은 뒤 추가된 프리셋이 조용히 사라진다.
  assert.doesNotMatch(scanOptions, /json: \{ presets: \[/);
  assert.match(scanOptions, /`\/scan-presets\/item\/\$\{encodeURIComponent\(trimmed\)\}`[\s\S]*?method: "PUT"/);
  assert.match(scanOptions, /`\/scan-presets\/item\/\$\{encodeURIComponent\(presetId\)\}`, \{ method: "DELETE" \}/);
  // 이관은 create_only — 서버에 이미 있는 동명 프리셋을 덮어쓰지 않는다.
  assert.match(scanOptions, /\?create_only=true`/);

  // '같은 이름인가'는 서버 규칙(연속 공백 접기 + casefold)만 안다. 클라이언트가 재구현하면
  // 'Weekly  Full' 과 'weekly full' 을 다르게 보고 서버는 중복이라 거절하는 불일치가 생긴다.
  assert.doesNotMatch(scanOptions, /name\.trim\(\)\.toLowerCase\(\)/);
  assert.match(scanOptions, /setPresetId\(saved\.name \|\| trimmed\)/);
});

test("timing controls and presets resolve to one backend-visible timing", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx");
  const normalize = scanOptions.slice(
    scanOptions.indexOf("function normalizeSelections"),
    scanOptions.indexOf("function protocolPorts"),
  );
  assert.match(normalize, /const selectedTiming = TIMING_KEYS\.find/);
  assert.match(normalize, /TIMING_KEYS\.forEach\(\(\[key\]\) => next\.delete\(key\)\)/);
  assert.match(normalize, /if \(selectedTiming\) next\.add\(selectedTiming\)/);

  const toggle = scanOptions.slice(
    scanOptions.indexOf("function toggle(k)"),
    scanOptions.indexOf("function toggleNse(k)"),
  );
  assert.match(toggle, /TIMING_KEYS\.some\(\(\[key\]\) => key === k\)/);
  assert.match(toggle, /TIMING_KEYS\.forEach\(\(\[key\]\) => n\.delete\(key\)\)/);
  assert.match(toggle, /n\.add\(k\)/);
});

test("staged preview mirrors discovery, protocol sweeps, and per-host service probes", () => {
  const scanOptions = source("../src/ui/ScanOptions.jsx").replace(/\r\n/g, "\n");
  const staged = scanOptions.slice(
    scanOptions.indexOf("if (staged) {"),
    scanOptions.indexOf("return out;\n    }", scanOptions.indexOf("if (staged) {")) + 16,
  );
  for (const title of ["호스트 발견", "TCP 포트 탐색", "TCP 서비스 식별", "UDP 포트 탐색", "UDP 서비스 식별"]) {
    assert.match(staged, new RegExp(`title: "${title}"`));
  }
  assert.match(staged, /"-sn", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n"/);
  assert.match(staged, /"-n",\s*timing, "--reason", "--max-retries", "2"/);
  assert.match(staged, /"--reason", timing, "--max-retries", "2", "-p", "T:/);
  assert.match(staged, /versionFlag === "--version-light" && versionFlag, "--open", "--reason", timing/);
  assert.match(staged, /const defeatRst = scanFlag === "-sS" \? "--defeat-rst-ratelimit" : ""/);
  assert.match(staged, /"--min-hostgroup", "64", defeatRst/);
  assert.match(staged, /"--max-parallelism", "100"/);
  assert.match(staged, /"T:<TCP 탐색에서 열린 포트>"/);
  assert.match(staged, /"U:<UDP 탐색에서 열린 포트>"/);
  assert.match(staged, /versionFlag === "--version-light" && versionFlag/);
  assert.match(staged, /"<호스트 1대>"/);
  assert.match(source("../src/views/Scans.jsx"), /targets=\{targetList\} excludes=\{previewExcludes\} staged=\{staged\}/);
  assert.match(scanOptions, /단계별 명령 템플릿/);
});

test("scan screen shows target and run first, with everything else folded away", () => {
  const scans = source("../src/views/Scans.jsx");
  const css = source("../src/styles.css");
  // 세부 설정은 기본 접힘 — 체크박스 80여 개와 명령 미리보기가 실행 버튼 앞을 가로막으면
  // 화면을 처음 보는 사람은 무엇을 해야 하는지 읽어낼 수 없다.
  assert.match(scans, /const \[showAdvanced, setShowAdvanced\] = useState\(false\)/);
  assert.match(scans, /className="scan-advanced" style=\{\{ display: showAdvanced \? "block" : "none" \}\}/);
  // 옵션 빌더는 접혀 있어도 마운트를 유지해야 raw 모드의 '채우기'가 최신 명령을 얻는다.
  assert.doesNotMatch(scans, /showAdvanced && <ScanOptions/);
  // 세부 설정을 펼치지 않아도 무엇을 하려는지 한 줄로 확인하고 실행할 수 있어야 한다.
  assert.match(scans, /const planSummary = \(\(\) => \{/);
  assert.match(scans, /className="scan-summary"/);
  assert.match(css, /\.scan-summary\s*\{/);
  // 가져오기는 '스캔한다'와 다른 작업이라 실행 버튼 옆이 아니라 따로 둔다.
  assert.match(scans, /className="scan-import-row"/);
});

test("folder import drops interrupted scan output before uploading it", async () => {
  const { prepareImportGroups, isInterruptedPath } = await import("../src/lib/scanImports.js");

  assert.ok(isInterruptedPath("scans/interrupted/scan.x.tcp_discovery.interrupted.xml"));
  assert.ok(isInterruptedPath("scan.x.tcp_identify.interrupted.xml"));
  assert.ok(isInterruptedPath("scans/interrupted/scan.x.xml"));
  // 'interrupted' 가 이름의 일부일 뿐인 온전한 결과는 막지 않는다.
  assert.equal(isInterruptedPath("scans/interrupted_hosts_report.xml"), false);
  assert.equal(isInterruptedPath("scans/scan.x.tcp_discovery.xml"), false);

  const file = (path) => ({
    webkitRelativePath: path,
    name: path.split("/").at(-1),
    text: async () => "",
  });
  const plan = await prepareImportGroups([
    file("scans/scan.a.tcp_discovery.xml"),
    file("scans/interrupted/scan.a.tcp_identify.interrupted.xml"),
  ]);

  const uploaded = plan.groups.flatMap((group) => group.files.map((f) => f.name));
  assert.deepEqual(uploaded, ["scans/scan.a.tcp_discovery.xml"]);
  assert.equal(plan.interruptedXmlCount, 1);
});

test("import summary says how many interrupted scans it left out", async () => {
  const { formatImportSummary } = await import("../src/lib/scanImports.js");
  const message = formatImportSummary({
    imported: 1, groupCount: 1, succeededGroups: 1, fileCount: 1,
    selectedXmlCount: 1, interruptedXmlCount: 2, counts: {}, closureModes: [],
  });
  assert.match(message, /중단된 스캔 2개 제외/);
});

test("interrupted output that never uploads is not counted as a failure", async () => {
  const { runImportGroups } = await import("../src/lib/scanImports.js");
  const summary = await runImportGroups(
    { groups: [], selectedXmlCount: 0, skippedXmlCount: 0, interruptedXmlCount: 3 },
    async () => ({}),
  );
  assert.equal(summary.interruptedXmlCount, 3);
  assert.equal(summary.hasFailures, false);
});

test("scan history shows scope, not the raw command line", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /<th>스캔 범위<\/th>/);
  assert.match(scans, /<ScanScope summary=\{s\.summary\}/);
  // 원문 명령은 사라지지 않고 상세로 내려간다.
  assert.match(scans, /scan-detail-command/);
  assert.doesNotMatch(scans, /whiteSpace: "normal", color: "var\(--muted\)" \}\}>\{s\.command\}/);
});

test("deleting a scan is admin-only and says what else it removes", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /const canDelete = user\.role === "admin"/);
  assert.match(scans, /window\.confirm\(/);
  assert.match(scans, /발견 관리에서 함께 삭제됩니다/);
  assert.match(scans, /method: "DELETE"/);
});

test("web scan can exclude ports, and the estimate sees the same value", () => {
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /id="scan-exclude-ports"/);
  // 실행 두 경로와 예상치 호출이 모두 같은 값을 실어 보낸다.
  assert.equal((scans.match(/exclude_ports: excludePorts/g) || []).length, 3);
});

test("findings colour indicators are per-element and persist", async () => {
  const findings = source("../src/views/Findings.jsx");
  assert.match(findings, /COLOR_ELEMENTS/);
  assert.match(findings, /localStorage\.setItem\(COLOR_KEY/);
  const colors = source("../src/lib/findingColors.js");
  for (const key of ["risk", "deadline", "status", "guess"]) {
    assert.ok(colors.includes(`key: "${key}"`), `${key} 토글이 없습니다`);
  }
  const { cellTone, loadColorFlags, COLOR_DEFAULTS } = await import("../src/lib/findingColors.js");
  assert.deepEqual(loadColorFlags({ getItem: () => "{oops" }), COLOR_DEFAULTS);
  const banned = { risk_level: "banned", status: "미조치", identification: "확인" };
  assert.equal(cellTone(banned, "risk_level", { risk: true }), "tone-high");
  assert.equal(cellTone(banned, "risk_level", { risk: false }), "");   // 끄면 색이 없다
  const guessed = { identification: "추측" };
  assert.equal(cellTone(guessed, "display_identity", { guess: true }), "tone-guess");
  assert.equal(cellTone(guessed, "display_identity", { guess: false }), "");
});

test("a completed scan's degraded-evidence note is not rendered as a failure reason", () => {
  // 포트 관측은 온전한데 NSE 소켓 오류만 있었던 실행. 백엔드가 이 둘을 분리해 두었는데
  // 화면에서 다시 '실패 원인'으로 합치면 의미가 도로 뭉개진다.
  const degraded = scanNotice({
    failure_code: "nse_degraded",
    failure_message: "NSE/소켓 오류가 있었습니다 — 포트 결과는 온전하지만 …",
  });
  assert.equal(degraded.tone, "notice");
  assert.equal(degraded.title, "참고 — 부가 정보 불완전");

  // 진짜 실패는 그대로 실패로 보여야 한다.
  const failed = scanNotice({
    failure_code: "nmap_xml_incomplete",
    failure_message: "nmap 이 결과 XML 을 끝맺지 못했습니다 …",
  });
  assert.equal(failed.tone, "failure");
  assert.equal(failed.title, "실패 원인");

  // 미관측은 '부가 정보 부족'과 다른 축이다. 응답하지 않은 호스트의 포트는 아예 못 본
  // 것이라, 같은 라벨로 그리면 '포트 결과는 온전'하다고 반대로 읽힌다. 그리고 이 실행은
  // status=done 으로 결과가 정상 인입된 실행이므로 '실패 원인'으로 그려서도 안 된다.
  const unobserved = scanNotice({
    failure_code: "observation_incomplete",
    failure_message: "응답하지 않은 호스트가 있어 발견 3건은 관측하지 못했습니다 …",
  });
  assert.equal(unobserved.tone, "notice");
  assert.equal(unobserved.title, "참고 — 일부 호스트 미관측");
  assert.notEqual(unobserved.title, degraded.title);

  assert.equal(scanNotice({}), null);
  // 뷰는 라벨을 직접 쓰지 않고 이 계약을 통해서만 그린다.
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /scanNotice\(\{/);
  assert.doesNotMatch(scans, /<b>실패 원인<\/b>/);
  assert.match(source("../src/styles.css"), /\.scan-failure-detail\.notice/);
});

test("an inferred-open port never reads on screen as a confirmed observation", () => {
  // 같은 open 이라도 syn-ack(응답을 받아 확인)과 no-response(못 받고 추정)는 증거 강도가
  // 전혀 다르다. UDP 는 무응답이 예외가 아니라 다수라, 이 구분이 화면에서 사라지면
  // 사용자는 추정을 관측으로 읽는다.
  const confirmed = { state: "open", state_evidence: "응답 확인", reason: "syn-ack" };
  const inferred = { state: "open|filtered", state_evidence: "무응답 추정",
                     reason: "no-response", needs_confirmation: true };

  // 확인된 건에는 군더더기를 붙이지 않는다 — 모든 행에 붙으면 신호가 죽는다.
  assert.equal(stateWithEvidence(confirmed), "open");
  assert.equal(stateWithEvidence(inferred), "open|filtered (무응답 추정)");
  assert.equal(needsConfirmation(confirmed), false);
  assert.equal(needsConfirmation(inferred), true);

  // reason 컬럼 이전에 인입된 행. '기록하지 않았다'와 '응답이 없었다'는 다른 사실이라
  // 재확인을 요구하지 않는다.
  const legacy = { state: "open", state_evidence: "미관측", reason: "" };
  assert.equal(stateWithEvidence(legacy), "open (미관측)");
  assert.equal(needsConfirmation(legacy), false);

  // 저장만 하고 안 쓰면 이 작업의 목적이 없어진다 — 표/내보내기와 상세에 실제로 실린다.
  assert.equal(cellValue(inferred, "state_evidence"), "무응답 추정");
  assert.equal(cellValue(inferred, "reason"), "no-response");
  const view = source("../src/views/Findings.jsx");
  assert.match(view, /stateWithEvidence\(finding\)/);
  assert.match(view, /needsConfirmation\(finding\)/);
});

test("a closed finding never wears the reason it had while it was open", () => {
  // 부재 기반 닫힘은 state 만 바꾸고 reason 은 열려 있던 시절의 syn-ack 을 그대로 둔다.
  // 해석만 고치고 원문을 옆에 그대로 두면 'closed · syn-ack' 이 되어 오독이 남는다.
  const closed = { state: "closed", state_evidence: "부재로 판정", reason: "syn-ack" };

  assert.equal(stateWithEvidence(closed), "closed (부재로 판정)");
  assert.equal(currentReason(closed), "");
  assert.equal(needsConfirmation(closed), false);

  // 닫힘을 응답으로 실제 확인한 경우에는 원문이 그대로 남는다.
  const refused = { state: "closed", state_evidence: "응답 확인", reason: "conn-refused" };
  assert.equal(currentReason(refused), "conn-refused");

  // 상세는 이 규칙을 통해서만 원문을 그린다.
  const view = source("../src/views/Findings.jsx");
  assert.match(view, /currentReason\(finding\)/);
  assert.doesNotMatch(view, /\{finding\.reason\}/);
});

test("every filter shares one exclude syntax", () => {
  // 화면마다 규칙이 다르면 외울 수 없다. 서버(parse_needle)와 같은 문법을 클라이언트
  // 전용 필터(자산대장)까지 같은 모듈로 쓴다.
  assert.deepEqual(parseNeedle("!ssh"), { needle: "ssh", negate: true });
  assert.deepEqual(parseNeedle("!!ssh"), { needle: "!ssh", negate: false });
  assert.deepEqual(parseNeedle("ssh"), { needle: "ssh", negate: false });

  assert.equal(matchesFilter(["ssh", "22"], "ssh"), true);
  assert.equal(matchesFilter(["ssh", "22"], "!ssh"), false);
  assert.equal(matchesFilter(["https", "443"], "!ssh"), true);
  // 빈 필터는 아무것도 거르지 않는다 - `!` 만 입력한 중간 상태에서 목록이 비면 안 된다.
  assert.equal(matchesFilter(["https"], "!"), true);
  assert.equal(matchesFilter(["https"], "  "), true);

  const findings = source("../src/views/Findings.jsx");
  const assets = source("../src/views/Assets.jsx");
  const history = source("../src/views/History.jsx");
  for (const view of [findings, assets, history]) {
    assert.match(view, /FILTER_HINT/, "제외 문법은 화면에서 안내돼야 한다");
  }
  assert.match(assets, /matchesFilter\(/);
});

test("an allowed finding is folded on a different axis than a resolved one", () => {
  // 규칙이 '허용'한 것과 사람이 '정상처리'한 것은 다른 사실이다. 하나로 묶으면 둘 중
  // 무엇 때문에 안 보이는지 알 수 없다.
  const view = source("../src/views/Findings.jsx");
  assert.match(view, /const \[hideAllowed, setHideAllowed\] = useState\(true\)/);
  assert.match(view, /qs\.set\("hide_allowed"/);
  assert.match(view, /허용 제외/);
  // 접힌 것을 펼쳤을 때 왜 보이는지 표에서 읽혀야 한다.
  assert.match(view, /finding\.allowed/);
  assert.match(view, /className="tag allowed"/);
  // 정상처리 토글과 독립적이어야 한다 - 같은 상태를 공유하면 축이 도로 합쳐진다.
  assert.ok(!/hideNormal\s*\|\|\s*hideAllowed/.test(view));
});

test("a rule's match count leads to the findings it actually matched", () => {
  // 건수만 보여 주면 '그래서 어떤 건데?' 를 매번 손으로 찾아야 한다. 서버 _match_count 와
  // 같은 기준이어야 건수와 목록이 어긋나지 않는다.
  assert.deepEqual(matchFocus({ kind: "service_rule", service: "telnet" }), {
    filters: { service: "telnet" }, match: "exact", hideNormal: false, hideAllowed: false,
  });
  assert.deepEqual(matchFocus({ kind: "port_rule", port: 3389, service: "" }), {
    filters: { port: "3389" }, match: "exact", hideNormal: false, hideAllowed: false,
  });
  assert.deepEqual(matchFocus({ kind: "product_rule", product: "vsftpd" }), {
    filters: { product: "vsftpd" }, match: "contains", hideNormal: false, hideAllowed: false,
  });
  // 허용 규칙의 매칭은 기본으로 접혀 있다 - 그대로 이동하면 빈 목록만 보인다.
  assert.equal(matchFocus({ kind: "cpe_rule", cpe: "openssh" }).hideAllowed, false);

  const rules = source("../src/views/Rules.jsx");
  assert.match(rules, /onShowMatches\(matchFocus\(r\)\)/);
  // 0 건은 볼 것이 없으므로 링크로 만들지 않는다.
  assert.match(rules, /r\.match_count && onShowMatches/);
  const app = source("../src/App.jsx");
  assert.match(app, /onShowMatches=\{focusFindings\}/);
  assert.match(app, /focus=\{findingsFocus\}/);
});

test("a wide findings table can be scrolled without leaving the rows", () => {
  // 기본 가로 스크롤바는 200행 아래에 있다 - 오른쪽 컬럼을 보려면 페이지 끝까지 내려가
  // 바를 잡고 다시 올라와야 해서 사실상 못 쓴다.
  const scroller = source("../src/ui/TableScroller.jsx");
  const css = source("../src/styles.css");
  assert.match(scroller, /overflowing &&/, "넘치지 않으면 군더더기를 더하지 않는다");
  assert.match(scroller, /role="scrollbar"/);
  assert.match(css, /\.table-scrollbar\s*\{[^}]*position: sticky;[^}]*bottom: 0;/);
  // 둘이 동시에 보이면 어느 쪽이 진짜인지 알 수 없다.
  assert.match(css, /\.table-scroll\.has-proxy::-webkit-scrollbar \{ height: 0; \}/);
  assert.match(source("../src/views/Findings.jsx"), /<TableScroller/);
});

test("a long fingerprint expands in place and collapses when the pointer leaves", () => {
  // 팝업이 아니라 셀 자체가 늘어나야 커서가 벗어나는 순간 원래대로 돌아온다.
  const css = source("../src/styles.css");
  assert.match(css, /\.pre-cell \{[\s\S]*?max-height: 2\.8em;/);
  assert.match(css, /\.pre-cell:hover, \.pre-cell:focus-visible \{[\s\S]*?max-height: 22em;/);
  assert.match(source("../src/views/Findings.jsx"), /className=\{"mono pre-cell"/);
});

test("a forced password change cannot be dismissed and says why", () => {
  const app = source("../src/App.jsx");
  const modal = source("../src/ui/PasswordModal.jsx");
  assert.match(app, /const mustChange = !!user\.must_change_password/);
  assert.match(app, /mandatory=\{mustChange\}/);
  // 닫을 수 있게 두면 아무것도 안 되는 빈 화면만 남는다.
  assert.match(modal, /if \(mandatory\) return;/);
  assert.match(modal, /\{!mandatory && <button type="button" className="sm" onClick=\{onClose\}>취소<\/button>\}/);
  // 왜 떴는지가 유일한 설명이므로 흐린 보조 텍스트로 두지 않는다.
  assert.match(modal, /\{notice && <p className="modal-notice">\{notice\}<\/p>\}/);
  assert.match(app, /INITIAL_ADMIN\.txt/);
});

test("an import that failed verification is not reported as a clean success", () => {
  const flagged = formatImportSummary({
    imported: 1, groupCount: 1, succeededGroups: 1, fileCount: 1, selectedXmlCount: 1,
    counts: { new: 2, closed: 0 },
    reviews: [{ file: "weekly.udp_identify.xml", mark: "재실행 권장", why: "NSE 결과가 없습니다." }],
  });
  assert.match(flagged, /검증 \[재실행 권장\] weekly\.udp_identify\.xml/);
  assert.match(flagged, /NSE 결과가 없습니다/);

  const clean = formatImportSummary({
    imported: 1, groupCount: 1, succeededGroups: 1, fileCount: 1, selectedXmlCount: 1,
    counts: { new: 2, closed: 0 }, reviews: [],
  });
  assert.doesNotMatch(clean, /검증/, "정상 결과에까지 딱지를 붙이면 신호가 죽는다");
});

test("a scan whose range was never recorded says so instead of showing a default", () => {
  // 예전에는 명령 표기가 argv 가 아니면 무조건 'TCP · 기본 1000개' 로 그려서, 전 포트
  // TCP+UDP 단계 스캔이 상위 1000개 TCP 스캔으로 보였다.
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /const unknown = !\(summary\.protocols \|\| \[\]\)\.length/);
  assert.match(scans, /is-unknown/);
  assert.match(source("../src/styles.css"), /\.scan-scope-ports\.is-unknown/);
});

test("long lists let the reader choose how much fits on one page", () => {
  const findings = source("../src/views/Findings.jsx");
  const history = source("../src/views/History.jsx");
  assert.ok(PAGE_SIZES.includes(200) && PAGE_SIZES.at(-1) >= 5000);
  assert.match(findings, /<PageSize value=\{pageSize\}/);
  // 예전에는 200건에서 잘린 채 총 건수만 보여 줘, 그 뒤가 있는지도 알 수 없었다.
  assert.match(history, /<PageSize value=\{size\}/);
  assert.match(history, /feed\.items\.length < feed\.total/);
});

test("an imported run is drawn exactly like one that ran in the web UI", () => {
  // 단독 스캐너로 돌렸다는 이유로 이력에서 덜 보여 줄 이유가 없다. 타임라인이 이미
  // 목록 응답에 실려 오면 추가 요청 없이 그대로 그린다.
  assert.equal(shouldLoadStages({ status: "done", name: "가져오기: weekly 자동 스캔 묶음",
                                  stages_json: [{ stage: "tcp_discovery" }] }), false);
  // 타임라인이 없는 단계 스캔은 여전히 받아온다.
  assert.equal(shouldLoadStages({ status: "done", command: "단계스캔(엔진) · TCP 443" }), true);
  const scans = source("../src/views/Scans.jsx");
  // 엔진 단계와 가져오기 단계를 같은 라벨 표에서 그린다.
  assert.match(scans, /tcp_discovery: "TCP 발견", tcp_identify: "TCP 식별", udp_identify: "UDP 식별"/);
  assert.match(scans, /withPersistedStages\(prev, list\)/);
});

test("a running scan says which batch and stage it is on", () => {
  // 퍼센트 하나만 보이면 몇 분째 같은 숫자를 보면서 진행 중인지 멈춘 것인지 알 수 없다.
  const scans = source("../src/views/Scans.jsx");
  assert.match(scans, /\{p\.stage && <span className="pill info"/);
  assert.match(scans, /p\.batch_label/);
  assert.match(scans, /p\.stage_hosts \? <span className="muted">· 대상/);
  assert.match(scans, /p\.hosts_up != null \? <span className="muted">· 응답/);
  // 배치 번호는 사람이 세는 방식(1부터)으로 보여준다.
  assert.match(scans, /배치 \$\{p\.batches_done \+ 1\}\/\$\{total\}/);
});

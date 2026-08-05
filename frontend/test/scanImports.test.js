import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  formatImportSummary,
  prepareImportGroups,
  runImportGroups,
} from "../src/lib/scanImports.js";


function selectedFile(path, body = "") {
  const name = path.replaceAll("\\", "/").split("/").at(-1);
  return {
    name,
    webkitRelativePath: path,
    text: async () => body,
  };
}


function strongManifest(xmlBasenames) {
  return JSON.stringify({
    tool: "scanops_scanner",
    import_contract: {
      schema: 1,
      units: xmlBasenames.map((xml_basename) => ({ xml_basename })),
    },
  });
}


test("strong manifests bind same-named XML to their own relative directory", async () => {
  const files = [
    selectedFile("picked/site-a/a.manifest.json", strongManifest(["result.xml"])),
    selectedFile("picked/site-a/result.xml", "<a/>"),
    selectedFile("picked/site-b/b.manifest.json", strongManifest(["result.xml"])),
    selectedFile("picked/site-b/result.xml", "<b/>"),
    selectedFile("picked/orphan.xml", "<orphan/>"),
  ];

  const plan = await prepareImportGroups(files);

  assert.deepEqual(plan.groups.map((group) => ({
    kind: group.kind,
    label: group.label,
    names: group.files.map((entry) => entry.name),
  })), [
    {
      kind: "manifest",
      label: "picked/site-a/a.manifest.json",
      names: ["picked/site-a/result.xml", "picked/site-a/a.manifest.json"],
    },
    {
      kind: "manifest",
      label: "picked/site-b/b.manifest.json",
      names: ["picked/site-b/result.xml", "picked/site-b/b.manifest.json"],
    },
    {
      kind: "legacy",
      label: "XML 가져오기",
      names: ["picked/orphan.xml"],
    },
  ]);
  assert.equal(plan.skippedXmlCount, 0);
  assert.deepEqual(plan.skippedXmlNames, []);

  const uploaded = [];
  const summary = await runImportGroups(plan, async (group) => {
    uploaded.push(...group.files.map((entry) => entry.name));
    return {
      imported: 1, failed: 0, file_count: 1, counts: {}, closure_mode: "manifest",
    };
  });
  assert.equal(uploaded.includes("picked/orphan.xml"), true);
  assert.match(formatImportSummary(summary), /^가져옴/);
});


test("a manifest skips only unclaimed diagnostics in its own directory", async () => {
  const plan = await prepareImportGroups([
    selectedFile("picked/run/run.manifest.json", strongManifest(["claimed.xml"])),
    selectedFile("picked/run/claimed.xml"),
    selectedFile("picked/run/partial-diagnostic.xml"),
    selectedFile("picked/legacy/orphan.xml"),
  ]);

  assert.deepEqual(plan.groups.map((group) => ({
    kind: group.kind,
    names: group.files.map((entry) => entry.name),
  })), [
    {
      kind: "manifest",
      names: ["picked/run/claimed.xml", "picked/run/run.manifest.json"],
    },
    {
      kind: "legacy",
      names: ["picked/legacy/orphan.xml"],
    },
  ]);
  assert.equal(plan.skippedXmlCount, 1);
  assert.deepEqual(plan.skippedXmlNames, ["picked/run/partial-diagnostic.xml"]);
});


test("legacy manifest claims import_xml_files by basename in its own directory", async () => {
  const oldManifest = JSON.stringify({
    tool: "scanops_scanner",
    import_xml_files: [
      "C:\\offline\\old.tcp_identify.xml",
      "/var/offline/old.udp_identify.xml",
    ],
  });
  const plan = await prepareImportGroups([
    selectedFile("picked/old/old.manifest.json", oldManifest),
    selectedFile("picked/old/old.tcp_identify.xml"),
    selectedFile("picked/old/old.udp_identify.xml"),
  ]);

  assert.equal(plan.groups.length, 1);
  assert.equal(plan.groups[0].kind, "manifest");
  assert.deepEqual(plan.groups[0].files.map((entry) => entry.name), [
    "picked/old/old.tcp_identify.xml",
    "picked/old/old.udp_identify.xml",
    "picked/old/old.manifest.json",
  ]);
});


test("valid empty manifests skip unclaimed XML without starting a legacy upload", async () => {
  const emptyManifests = [
    JSON.stringify({
      tool: "scanops_scanner",
      import_contract: { schema: 1, units: [] },
    }),
    JSON.stringify({
      tool: "scanops_scanner",
      import_xml_files: [],
    }),
  ];
  for (const [index, manifest] of emptyManifests.entries()) {
    const plan = await prepareImportGroups([
      selectedFile(`picked/empty-${index}.manifest.json`, manifest),
      selectedFile("picked/leftover.xml"),
    ]);
    let uploadCalls = 0;
    const summary = await runImportGroups(plan, async () => {
      uploadCalls += 1;
      return {};
    });
    assert.deepEqual(plan.groups, []);
    assert.equal(plan.skippedXmlCount, 1);
    assert.equal(uploadCalls, 0);
    assert.match(formatImportSummary(summary), /^가져오기 실패.*미참조 XML 1개 건너뜀/);
  }
});


test("XML-only selection keeps the observed-host legacy upload path", async () => {
  const plan = await prepareImportGroups([
    selectedFile("picked/one.xml"),
    selectedFile("picked/two.xml"),
  ]);
  assert.equal(plan.skippedXmlCount, 0);
  assert.deepEqual(plan.groups.map((group) => ({
    kind: group.kind,
    names: group.files.map((entry) => entry.name),
  })), [{ kind: "legacy", names: ["picked/one.xml", "picked/two.xml"] }]);
});


test("malformed recognized manifest fails before any upload group is returned", async () => {
  await assert.rejects(
    prepareImportGroups([
      selectedFile("picked/bad.manifest.json", "{not-json"),
      selectedFile("picked/result.xml"),
    ]),
    /bad\.manifest\.json.*JSON/,
  );
  await assert.rejects(
    prepareImportGroups([
      selectedFile("picked/bad.manifest.json", JSON.stringify({
        tool: "scanops_scanner",
        import_contract: { schema: 1, units: [{ xml_basename: "../result.xml" }] },
      })),
      selectedFile("picked/result.xml"),
    ]),
    /안전한 XML basename/,
  );
});


test("a later malformed or missing manifest claim prevents the first upload", async () => {
  const invalidTails = [
    selectedFile("picked/z-bad.manifest.json", "{not-json"),
    selectedFile("picked/z-missing.manifest.json", strongManifest(["missing.xml"])),
  ];
  for (const tail of invalidTails) {
    let uploadCalls = 0;
    await assert.rejects(async () => {
      const plan = await prepareImportGroups([
        selectedFile("picked/a-good.manifest.json", strongManifest(["good.xml"])),
        selectedFile("picked/good.xml"),
        tail,
      ]);
      await runImportGroups(plan, async () => {
        uploadCalls += 1;
        return {};
      });
    });
    assert.equal(uploadCalls, 0);
  }
});


test("recognized manifest envelope failures remain fail-closed", async () => {
  const invalid = [
    ["wrong tool", { tool: "other", import_contract: { schema: 1, units: [] } }],
    ["null contract", { tool: "scanops_scanner", import_contract: null }],
    ["unsupported schema", { tool: "scanops_scanner", import_contract: { schema: 2, units: [] } }],
    ["non-array units", { tool: "scanops_scanner", import_contract: { schema: 1, units: {} } }],
  ];
  for (const [name, manifest] of invalid) {
    await assert.rejects(
      prepareImportGroups([
        selectedFile(`picked/${name}.manifest.json`, JSON.stringify(manifest)),
        selectedFile("picked/unclaimed.xml"),
      ]),
      undefined,
      name,
    );
  }
});


test("two manifests cannot claim the same relative XML", async () => {
  await assert.rejects(
    prepareImportGroups([
      selectedFile("picked/one.manifest.json", strongManifest(["same.xml"])),
      selectedFile("picked/two.manifest.json", strongManifest(["same.xml"])),
      selectedFile("picked/same.xml"),
    ]),
    /중복.*same\.xml/,
  );
});


test("manifest preflight rejects a missing same-directory XML", async () => {
  await assert.rejects(
    prepareImportGroups([
      selectedFile("picked/site-a/a.manifest.json", strongManifest(["result.xml"])),
      selectedFile("picked/site-b/result.xml"),
    ]),
    /site-a.*result\.xml.*없습니다/,
  );
});


test("sequential group import aggregates successes, API failures, and request failures", async () => {
  const groups = [
    { kind: "manifest", label: "a.manifest.json", xmlCount: 1, files: [] },
    { kind: "manifest", label: "b.manifest.json", xmlCount: 2, files: [] },
    { kind: "manifest", label: "old.manifest.json", xmlCount: 1, files: [] },
  ];
  const order = [];
  const summary = await runImportGroups({
    groups, selectedXmlCount: 4, skippedXmlCount: 0, skippedXmlNames: [],
  }, async (group) => {
    order.push(group.label);
    if (group.label === "b.manifest.json") throw new Error("계약 불일치");
    if (group.label === "a.manifest.json") {
      return {
        imported: 1,
        failed: 0,
        file_count: 1,
        counts: { new: 2, closed: 1 },
        closure_mode: "manifest",
      };
    }
    return {
      imported: 0,
      failed: 1,
      file_count: 1,
      counts: { new: 0, closed: 0 },
      closure_mode: "observed-host",
      errors: [{ name: "orphan.xml", error: "XML 형식이 올바르지 않습니다." }],
    };
  });

  assert.deepEqual(order, ["a.manifest.json", "b.manifest.json", "old.manifest.json"]);
  assert.deepEqual(summary.counts, { new: 2, closed: 1 });
  assert.equal(summary.groupCount, 3);
  assert.equal(summary.succeededGroups, 2);
  assert.equal(summary.requestFailures, 1);
  assert.equal(summary.failed, 1);
  assert.equal(summary.fileCount, 2);
  assert.equal(summary.selectedXmlCount, 4);
  assert.deepEqual(summary.closureModes, ["manifest", "observed-host"]);
  assert.deepEqual(summary.errors, [
    "b.manifest.json: 계약 불일치",
    "old.manifest.json: orphan.xml: XML 형식이 올바르지 않습니다.",
  ]);

  const message = formatImportSummary(summary);
  assert.match(message, /^부분 가져옴/);
  assert.match(message, /그룹 2\/3/);
  assert.match(message, /요청 실패 1/);
  assert.match(message, /처리 XML 2\/4개/);
  assert.match(message, /인입 실패 1/);
  assert.match(message, /완료 실행 범위 \+ 관측 호스트 기준/);
  assert.match(message, /b\.manifest\.json: 계약 불일치/);
  assert.match(message, /orphan\.xml: XML 형식이 올바르지 않습니다/);
});


test("summary lead distinguishes total failure, partial import, and complete success", () => {
  const base = {
    groupCount: 1,
    succeededGroups: 1,
    requestFailures: 0,
    failed: 0,
    fileCount: 1,
    selectedXmlCount: 1,
    counts: {},
    closureModes: ["observed-host"],
    errors: [],
    skippedXmlCount: 0,
  };
  assert.match(formatImportSummary({ ...base, imported: 0 }), /^가져오기 실패/);
  assert.match(formatImportSummary({ ...base, imported: 1, failed: 1 }), /^부분 가져옴/);
  assert.match(formatImportSummary({ ...base, imported: 1 }), /^가져옴/);
});


test("Scans preflights and uploads each planned group through the existing endpoint", () => {
  const scans = readFileSync(new URL("../src/views/Scans.jsx", import.meta.url), "utf8");
  assert.match(scans, /const plan = await prepareImportGroups\(fileList\)/);
  assert.match(scans, /await runImportGroups\(plan, async \(group\)/);
  assert.match(scans, /uploadMany\("\/scans\/import-bundle", group\.files\)/);
  assert.match(scans, /formatImportSummary\(summary\)/);
  assert.match(scans, /summary\.hasFailures \? \{ type: "err" \}/);
});

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as XLSX from "xlsx";

import {
  assetColumnsFrom, buildAssetRecords, computeAutoMap, detectHeaderRow,
  diffAssetRecords, mergeAssetRecord, readWorkbook, unmergeFillWs,
  validateWorkbookArchive,
} from "../src/lib/assetImport.js";


function recordsFromWorkbook(data) {
  const parsed = readWorkbook(data);
  const result = unmergeFillWs(parsed.wb.Sheets[parsed.sheetNames[0]]);
  const headerRow = detectHeaderRow(result.aoa);
  const cols = assetColumnsFrom(result.aoa, headerRow);
  return buildAssetRecords(cols, computeAutoMap(cols));
}


test("the bundled SheetJS build is the pinned 0.20.3 release", () => {
  assert.equal(XLSX.version, "0.20.3");
});


test("vendored SheetJS hash, dependency path, and license match the supply contract", () => {
  const archive = readFileSync(new URL("../vendor/xlsx-0.20.3.tgz", import.meta.url));
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const packageLock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  const installed = JSON.parse(readFileSync(new URL("../node_modules/xlsx/package.json", import.meta.url), "utf8"));
  const notices = readFileSync(new URL("../../THIRD_PARTY_NOTICES.md", import.meta.url), "utf8");
  const sha256 = createHash("sha256").update(archive).digest("hex").toUpperCase();
  const integrity = `sha512-${createHash("sha512").update(archive).digest("base64")}`;
  const locked = packageLock.packages["node_modules/xlsx"];

  assert.equal(sha256, "8DC73FC3B00203E72D176E85B50938627C7B086E607C682E8D3C22C02BB99FE8");
  assert.equal(packageJson.dependencies.xlsx, "file:vendor/xlsx-0.20.3.tgz");
  assert.equal(locked.version, "0.20.3");
  assert.equal(locked.resolved, "file:vendor/xlsx-0.20.3.tgz");
  assert.equal(locked.integrity, integrity);
  assert.equal(locked.license, "Apache-2.0");
  assert.equal(installed.version, "0.20.3");
  assert.equal(installed.license, "Apache-2.0");
  assert.match(notices, new RegExp(sha256));
  assert.match(notices, /Source: `https:\/\/cdn\.sheetjs\.com\/xlsx-0\.20\.3\/xlsx-0\.20\.3\.tgz`/);
});


test("vendored SheetJS parses a representative merged asset workbook", () => {
  const ws = XLSX.utils.aoa_to_sheet([
    ["자산대장", ""],
    ["IP", "부서"],
    ["127.0.0.1", "보안팀"],
  ]);
  ws["!merges"] = [XLSX.utils.decode_range("A1:B1")];
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "assets");
  const data = XLSX.write(wb, { type: "array", bookType: "xlsx" });

  const parsed = readWorkbook(data);
  const result = unmergeFillWs(parsed.wb.Sheets.assets);
  const headerRow = detectHeaderRow(result.aoa);
  const cols = assetColumnsFrom(result.aoa, headerRow);
  const records = buildAssetRecords(cols, computeAutoMap(cols));

  assert.equal(result.mergeCount, 1);
  assert.equal(headerRow, 1);
  assert.equal(records[0].ip, "127.0.0.1");
  assert.equal(records[0].dept, "보안팀");
});


test("oversized worksheet dimensions are rejected before materializing cells", () => {
  assert.throws(
    () => unmergeFillWs({ "!ref": "A1:A100001" }),
    /처리 한도/,
  );
  assert.throws(
    () => unmergeFillWs({ "!ref": "XFD100001:XFD100001" }),
    /처리 한도/,
  );
  assert.throws(
    () => unmergeFillWs({
      "!ref": "A1",
      "!merges": [XLSX.utils.decode_range("A1:A100001")],
    }),
    /처리 한도/,
  );
});


test("SheetJS parses legacy XLS and CSV asset files", () => {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
    ["IP", "부서"], ["10.0.0.1", "보안팀"],
  ]), "assets");
  const xls = XLSX.write(wb, { type: "array", bookType: "biff8" });
  const csv = new TextEncoder().encode("\ufeffIP,부서\r\n10.0.0.2,운영팀\r\n");

  assert.deepEqual(recordsFromWorkbook(xls)[0], {
    ip: "10.0.0.1", dept: "보안팀", extra: {},
  });
  assert.deepEqual(recordsFromWorkbook(csv)[0], {
    ip: "10.0.0.2", dept: "운영팀", extra: {},
  });
});


test("CSV grid limits fail before SheetJS at the production file-size boundary", () => {
  const wideAtBoundary = new Uint8Array(25 * 1024 * 1024);
  wideAtBoundary.fill(0x2c); // commas: far more than 512 columns in one row
  assert.throws(() => readWorkbook(wideAtBoundary), /처리 한도/);

  const tooManyRows = new TextEncoder().encode("a\r\n".repeat(100_001));
  assert.throws(() => readWorkbook(tooManyRows), /처리 한도/);

  const fiveHundredColumns = `${Array(500).fill("a").join(",")}\n`;
  const tooManyGridCells = new TextEncoder().encode(fiveHundredColumns.repeat(4_001));
  assert.throws(() => readWorkbook(tooManyGridCells), /처리 한도/);
});


test("CSV preflight preserves quoted separators and CRLF records", () => {
  const csv = new TextEncoder().encode(
    'IP,note\r\n"10.0.0.8","comma, semicolon; tab\t and pipe| stay quoted"\r\n',
  );
  const parsed = readWorkbook(csv);
  const { aoa } = unmergeFillWs(parsed.wb.Sheets[parsed.sheetNames[0]]);
  assert.deepEqual(aoa[1], ["10.0.0.8", "comma, semicolon; tab\t and pipe| stay quoted"]);
});


test("CSV preflight matches SheetJS quote rules and fixes the detected separator", () => {
  const embeddedQuoteWide = new TextEncoder().encode(
    `a"literal,${"b,".repeat(512)}z"\n`,
  );
  assert.throws(() => readWorkbook(embeddedQuoteWide), /처리 한도/);

  const punctuationCell = new TextEncoder().encode(
    `IP,note\r\n10.0.0.9,${"value;".repeat(600)}\r\n`,
  );
  const parsed = readWorkbook(punctuationCell);
  const { aoa } = unmergeFillWs(parsed.wb.Sheets[parsed.sheetNames[0]]);
  assert.equal(aoa[0].length, 2);
  assert.equal(aoa[1][0], "10.0.0.9");

  const semicolonCsv = new TextEncoder().encode("IP;dept\r\n10.0.0.10;Security\r\n");
  const semicolonParsed = readWorkbook(semicolonCsv);
  const semicolonAoa = unmergeFillWs(
    semicolonParsed.wb.Sheets[semicolonParsed.sheetNames[0]],
  ).aoa;
  assert.deepEqual(semicolonAoa[1], ["10.0.0.10", "Security"]);
});


test("XLSX expanded-size preflight runs before workbook parsing", () => {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([["IP"], ["10.0.0.3"]]), "assets");
  const data = XLSX.write(wb, { type: "array", bookType: "xlsx" });

  assert.throws(() => validateWorkbookArchive(data, 1), /압축 해제 크기/);
  assert.equal(recordsFromWorkbook(data)[0].ip, "10.0.0.3");
});


test("prefixed XLSX cannot bypass ZIP preflight", () => {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([
    ["IP", "부서"], ["10.0.0.7", "보안팀"],
  ]), "assets");
  const xlsx = new Uint8Array(XLSX.write(wb, { type: "array", bookType: "xlsx" }));
  const prefixed = new Uint8Array(xlsx.byteLength + 1);
  prefixed[0] = 0x41;
  prefixed.set(xlsx, 1);

  const started = performance.now();
  assert.throws(() => readWorkbook(prefixed), /XLSX ZIP 앞에 허용되지 않는 데이터/);
  assert.ok(performance.now() - started < 1000, "prefixed ZIP must fail before SheetJS parsing");

  assert.equal(recordsFromWorkbook(xlsx)[0].ip, "10.0.0.7");
});


test("record building preserves unmapped fields and carries mapped blanks", () => {
  const aoa = [["IP", "부서", "OS"], ["10.0.0.4", "", ""]];
  const cols = assetColumnsFrom(aoa, 0);
  const records = buildAssetRecords(cols, computeAutoMap(cols), [2]);
  const record = records[0];

  assert.equal(Object.hasOwn(record, "hostname"), false);
  assert.equal(Object.hasOwn(record, "owner"), false);
  assert.equal(Object.hasOwn(record, "dept"), true);
  assert.equal(record.dept, "");
  assert.deepEqual(record.extra, { OS: "" });
});


test("preview diff uses the same core and extra merge-clear semantics as bulk upsert", () => {
  const current = {
    id: 7, ip: "10.0.0.5", hostname: "server-a", dept: "보안팀", owner: "김담당",
    contact: "1234", asset_no: "A-1", note: "keep", extra: { OS: "Linux", Rack: "R1" },
  };
  const omitted = { ip: "10.0.0.5", extra: {} };
  assert.deepEqual(mergeAssetRecord(current, omitted), current);
  assert.equal(diffAssetRecords([omitted], [current]).same, 1);

  const patch = { ip: "10.0.0.5", dept: "", extra: { Rack: "", Zone: "A" } };
  const merged = mergeAssetRecord(current, patch);
  assert.equal(merged.dept, "");
  assert.equal(merged.owner, "김담당");
  assert.deepEqual(merged.extra, { OS: "Linux", Zone: "A" });

  const diff = diffAssetRecords([patch], [current]);
  assert.equal(diff.changed.length, 1);
  assert.deepEqual(diff.changed[0].changes, [
    { label: "부서", old: "보안팀", neu: "" },
    { label: "Rack", old: "R1", neu: "" },
    { label: "Zone", old: "", neu: "A" },
  ]);
});


test("duplicate import rows are folded in backend order for preview", () => {
  const current = { id: 1, ip: "10.0.0.6", dept: "기존", owner: "", extra: {} };
  const diff = diffAssetRecords([
    { ip: "10.0.0.6", dept: "첫째", extra: {} },
    { ip: "10.0.0.6", owner: "둘째", extra: {} },
  ], [current]);

  assert.equal(diff.changed.length, 1);
  assert.deepEqual(diff.changed[0].changes, [
    { label: "부서", old: "기존", neu: "첫째" },
    { label: "담당자", old: "", neu: "둘째" },
  ]);
});

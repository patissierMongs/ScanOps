// 새 하이브리드 로직 검증 — 결합셀 분리(담당자→owner/contact) + 커스텀 필드 + 누락정리.
import { readFileSync, writeFileSync } from "node:fs";
import {
  readWorkbook, unmergeFillWs, detectHeaderRow, assetColumnsFrom, computeAutoMap, buildAssetRecords,
} from "../frontend/src/lib/assetImport.js";

const buf = readFileSync("C:/Users/upica/OneDrive/Documents/SAMPLE1.xlsx");
const { wb, sheetNames } = readWorkbook(buf);
const { aoa } = unmergeFillWs(wb.Sheets[sheetNames[0]]);
const hr = detectHeaderRow(aoa);
const cols = assetColumnsFrom(aoa, hr);
const mapping = computeAutoMap(cols); // {dept:0, owner:5, ip:7, asset_no:8}

// 결합셀 분리: 담당자(idx5) "좋은시스템, 김일번, 010-..." → owner=part1, contact=part2
mapping.owner = { col: 5, sep: ",", part: 1 };
mapping.contact = { col: 5, sep: ",", part: 2 };
// 커스텀 보존: 종류(2)·제조사(3)·운영체제(4)·사번(6)
const extraCols = [2, 3, 4, 6];

const records = buildAssetRecords(cols, mapping, extraCols);
writeFileSync("live_sample/sample1_hybrid.json", JSON.stringify({ headerRow: hr, mapping, records }, null, 1));
console.log("records:", records.length, "| owner[0]:", records[0].owner, "| contact[0]:", records[0].contact);
console.log("missing manufacturer row(서버, '-'):", JSON.stringify(records[3].extra));

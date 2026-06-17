// 사용자의 실제 SAMPLE1.xlsx 를 프론트 임포트 파이프라인 그대로 통과시켜 결과 확인.
import { readFileSync, writeFileSync } from "node:fs";
import {
  readWorkbook, unmergeFillWs, detectHeaderRow, assetColumnsFrom, computeAutoMap, buildAssetRecords,
} from "../frontend/src/lib/assetImport.js";

const buf = readFileSync("C:/Users/upica/OneDrive/Documents/SAMPLE1.xlsx");
const { wb, sheetNames } = readWorkbook(buf);
const ws = wb.Sheets[sheetNames[0]];
const { aoa, mergeCount } = unmergeFillWs(ws);
const headerRow = detectHeaderRow(aoa);
const cols = assetColumnsFrom(aoa, headerRow);
const mapping = computeAutoMap(cols);
const records = buildAssetRecords(cols, mapping);

const out = {
  sheetNames, mergeCount, detectedHeaderRow: headerRow,
  headerRowText: aoa[headerRow],
  columns: cols.map((c) => ({ idx: c.index, header: c.header, sample: c.values[0] })),
  autoMap: mapping,
  mappedFieldNames: Object.fromEntries(Object.entries(mapping).map(([k, v]) => [k, cols[v]?.header])),
  records,
};
writeFileSync("live_sample/sample1_result.json", JSON.stringify(out, null, 1));
console.log("done; headerRow=", headerRow, "records=", records.length);

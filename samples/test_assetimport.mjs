// 자산 임포트 순수로직 단위검증 — 병합셀 forward-fill·헤더감지·자동매핑.
import * as XLSX from "../frontend/node_modules/xlsx/xlsx.mjs";
import {
  unmergeFillWs, detectHeaderRow, assetColumnsFrom, computeAutoMap, buildAssetRecords,
} from "../frontend/src/lib/assetImport.js";

const aoa = [
  ["자산 관리 대장"],                              // 0: 제목 행(단일값 → 헤더 후보 제외)
  ["자산코드", "IP주소", "관리부서", "관리자"],     // 1: 진짜 헤더
  ["SRV-1", "10.0.0.1", "인프라운영팀", "김도현"],
  ["SRV-2", "10.0.0.2", "", "이수민"],             // 부서 병합(위 값 채움 대상)
  ["SRV-3", "10.0.0.3", "보안팀", "박정우"],
];
const ws = XLSX.utils.aoa_to_sheet(aoa);
// 관리부서(C열, idx2) 2~3행 병합 → 해제 시 SRV-2 부서 = 인프라운영팀
ws["!merges"] = [{ s: { r: 2, c: 2 }, e: { r: 3, c: 2 } }];

const { aoa: filled, mergeCount } = unmergeFillWs(ws);
const hr = detectHeaderRow(filled);
const cols = assetColumnsFrom(filled, hr);
const mapping = computeAutoMap(cols);
const recs = buildAssetRecords(cols, mapping);

const checks = [];
const ok = (name, cond) => checks.push([name, !!cond]);
ok("mergeCount=1", mergeCount === 1);
ok("headerRow=1(제목행 건너뜀)", hr === 1);
ok("automap ip->1", mapping.ip === 1);
ok("automap asset_no->0", mapping.asset_no === 0);
ok("automap dept->2", mapping.dept === 2);
ok("automap owner->3", mapping.owner === 3);
ok("records=3", recs.length === 3);
ok("병합 forward-fill: SRV-2 dept=인프라운영팀", recs[1].dept === "인프라운영팀");
ok("ip 정상", recs[0].ip === "10.0.0.1");

let pass = true;
for (const [name, c] of checks) { console.log((c ? "PASS" : "FAIL") + " · " + name); if (!c) pass = false; }
console.log(pass ? "\nALL PASS" : "\nFAILED");
process.exit(pass ? 0 : 1);

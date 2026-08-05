const XML_SUFFIX = ".xml";
const MANIFEST_SUFFIX = ".manifest.json";


function selectedPath(file) {
  let value = String(file?.webkitRelativePath || file?.name || "").replaceAll("\\", "/");
  while (value.startsWith("./")) value = value.slice(2);
  const parts = value.split("/");
  if (!value || value.startsWith("/") || parts.some((part) => !part || part === "." || part === "..")) {
    throw new Error(`가져오기 파일 경로가 올바르지 않습니다: ${value || "(빈 경로)"}`);
  }
  return parts.join("/");
}


function parentPath(path) {
  const parts = path.split("/");
  parts.pop();
  return parts.join("/");
}


function safeBasename(value, manifestPath, allowPath = false) {
  if (typeof value !== "string" || !value) {
    throw new Error(`${manifestPath}: 안전한 XML basename이 필요합니다.`);
  }
  const normalized = value.replaceAll("\\", "/");
  const basename = normalized.split("/").at(-1);
  if (
    !basename
    || basename === "."
    || basename === ".."
    || basename.includes(":")
    || !basename.toLowerCase().endsWith(XML_SUFFIX)
    || (!allowPath && normalized !== basename)
  ) {
    throw new Error(`${manifestPath}: 안전한 XML basename이 아닙니다: ${value}`);
  }
  return basename;
}


function manifestClaims(text, manifestPath) {
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new Error(`${manifestPath}: manifest JSON 형식이 올바르지 않습니다.`);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error(`${manifestPath}: manifest JSON 객체가 필요합니다.`);
  }
  if (manifest.tool !== "scanops_scanner") {
    throw new Error(`${manifestPath}: ScanOps standalone manifest가 아닙니다.`);
  }

  let values;
  if (Object.hasOwn(manifest, "import_contract")) {
    const contract = manifest.import_contract;
    if (!contract || typeof contract !== "object" || Array.isArray(contract)
        || contract.schema !== 1 || !Array.isArray(contract.units)) {
      throw new Error(`${manifestPath}: import_contract 형식이 올바르지 않습니다.`);
    }
    values = contract.units.map((unit) => {
      if (!unit || typeof unit !== "object" || Array.isArray(unit)) {
        throw new Error(`${manifestPath}: import_contract unit 형식이 올바르지 않습니다.`);
      }
      return safeBasename(unit.xml_basename, manifestPath);
    });
  } else {
    if (!Array.isArray(manifest.import_xml_files)) {
      throw new Error(`${manifestPath}: 구형 manifest의 import_xml_files 목록이 올바르지 않습니다.`);
    }
    values = manifest.import_xml_files.map((value) => safeBasename(value, manifestPath, true));
  }
  if (new Set(values).size !== values.length) {
    throw new Error(`${manifestPath}: manifest에 중복 XML claim이 있습니다.`);
  }
  return values;
}


/**
 * Preflight a browser file/folder selection into one existing single-manifest request per
 * standalone run. No upload starts until every manifest and claim has been checked.
 */
export async function prepareImportGroups(fileList) {
  const entries = [...fileList]
    .map((file) => ({ file, name: selectedPath(file) }))
    .filter((entry) => {
      const lower = entry.name.toLowerCase();
      return lower.endsWith(XML_SUFFIX) || lower.endsWith(MANIFEST_SUFFIX);
    })
    .sort((a, b) => a.name.localeCompare(b.name));
  const xmls = entries.filter((entry) => entry.name.toLowerCase().endsWith(XML_SUFFIX));
  const manifests = entries.filter((entry) => entry.name.toLowerCase().endsWith(MANIFEST_SUFFIX));
  if (!xmls.length) throw new Error("가져올 .xml 파일이 없습니다");

  const xmlByPath = new Map();
  for (const entry of xmls) {
    if (xmlByPath.has(entry.name)) {
      throw new Error(`선택 항목에 중복 XML 경로가 있습니다: ${entry.name}`);
    }
    xmlByPath.set(entry.name, entry);
  }

  // Read and validate every manifest before returning the first executable group.
  const preparedManifests = [];
  for (const entry of manifests) {
    let text;
    try {
      text = await entry.file.text();
    } catch {
      throw new Error(`${entry.name}: manifest 파일을 읽을 수 없습니다.`);
    }
    preparedManifests.push({ entry, claims: manifestClaims(text, entry.name) });
  }

  const claimed = new Set();
  const groups = [];
  const manifestDirectories = new Set(
    preparedManifests.map(({ entry }) => parentPath(entry.name)),
  );
  for (const { entry: manifest, claims } of preparedManifests) {
    if (!claims.length) continue;
    const directory = parentPath(manifest.name);
    const groupXmls = [];
    for (const basename of claims) {
      const path = directory ? `${directory}/${basename}` : basename;
      const xml = xmlByPath.get(path);
      if (!xml) {
        throw new Error(`${manifest.name}: 같은 디렉터리의 ${path} 파일이 없습니다.`);
      }
      if (claimed.has(path)) {
        throw new Error(`${manifest.name}: XML claim이 중복되었습니다: ${path}`);
      }
      claimed.add(path);
      groupXmls.push(xml);
    }
    groups.push({
      kind: "manifest",
      label: manifest.name,
      xmlCount: groupXmls.length,
      files: [...groupXmls, manifest],
    });
  }

  const remaining = xmls.filter((entry) => !claimed.has(entry.name));
  const skipped = remaining.filter((entry) => manifestDirectories.has(parentPath(entry.name)));
  const legacy = remaining.filter((entry) => !manifestDirectories.has(parentPath(entry.name)));
  if (legacy.length) {
    groups.push({
      kind: "legacy",
      label: "XML 가져오기",
      xmlCount: legacy.length,
      files: legacy,
    });
  }
  return {
    groups,
    selectedXmlCount: xmls.length,
    skippedXmlCount: skipped.length,
    skippedXmlNames: skipped.map((entry) => entry.name),
  };
}


function number(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}


function errorText(value) {
  return String(value || "업로드 실패").replace(/\s+/g, " ").slice(0, 180);
}


/** Run preflighted groups in order, preserving successful earlier groups when a later one fails. */
export async function runImportGroups(plan, uploadGroup) {
  const groups = plan.groups;
  const summary = {
    groupCount: groups.length,
    succeededGroups: 0,
    requestFailures: 0,
    imported: 0,
    failed: 0,
    fileCount: 0,
    selectedXmlCount: number(plan.selectedXmlCount),
    skippedXmlCount: number(plan.skippedXmlCount),
    skippedXmlNames: [...(plan.skippedXmlNames || [])],
    counts: {},
    closureModes: [],
    errors: [],
  };
  for (const group of groups) {
    try {
      const result = await uploadGroup(group);
      summary.succeededGroups += 1;
      summary.imported += number(result?.imported);
      summary.failed += number(result?.failed);
      summary.fileCount += number(result?.file_count);
      for (const [key, value] of Object.entries(result?.counts || {})) {
        summary.counts[key] = number(summary.counts[key]) + number(value);
      }
      if (result?.closure_mode && !summary.closureModes.includes(result.closure_mode)) {
        summary.closureModes.push(result.closure_mode);
      }
      for (const item of Array.isArray(result?.errors) ? result.errors : []) {
        const name = item && typeof item === "object" ? item.name : "";
        const detail = item && typeof item === "object" ? (item.error || item.detail) : item;
        summary.errors.push(`${group.label}: ${name ? `${name}: ` : ""}${errorText(detail)}`);
      }
    } catch (error) {
      summary.requestFailures += 1;
      summary.errors.push(`${group.label}: ${errorText(error?.message || error)}`);
    }
  }
  summary.hasFailures = summary.requestFailures > 0
    || summary.failed > 0
    || summary.errors.length > 0
    || summary.skippedXmlCount > 0;
  return summary;
}


export function formatImportSummary(summary) {
  const counts = summary.counts || {};
  const modes = summary.closureModes || [];
  const imported = number(summary.imported);
  const hasFailures = number(summary.requestFailures) > 0
    || number(summary.failed) > 0
    || Boolean(summary.errors?.length)
    || number(summary.skippedXmlCount) > 0;
  const lead = imported === 0 ? "가져오기 실패" : hasFailures ? "부분 가져옴" : "가져옴";
  const closure = modes.includes("manifest") && modes.includes("observed-host")
    ? "완료 실행 범위 + 관측 호스트 기준"
    : modes.includes("manifest") ? "완료 실행 범위"
      : modes.includes("observed-host") ? "관측 호스트 기준" : "";
  let message = `${lead} · 그룹 ${number(summary.succeededGroups)}/${number(summary.groupCount)}`;
  if (summary.requestFailures) message += ` (요청 실패 ${number(summary.requestFailures)})`;
  message += ` · 결과 ${imported}건 / 처리 XML ${number(summary.fileCount)}/${number(summary.selectedXmlCount)}개`;
  if (summary.failed) message += ` (인입 실패 ${number(summary.failed)})`;
  message += ` · 신규 ${number(counts.new)} / 닫힘 ${number(counts.closed)}`;
  if (closure) message += ` · ${closure}`;
  if (summary.skippedXmlCount) message += ` · 미참조 XML ${number(summary.skippedXmlCount)}개 건너뜀`;
  if (summary.errors?.length) message += ` · 실패: ${summary.errors.join(" | ")}`;
  return message;
}

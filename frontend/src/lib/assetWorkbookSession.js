import { readWorkbook, unmergeFillWs } from "./assetImport.js";


const errorMessage = (error) =>
  error instanceof Error && error.message ? error.message : "자산 파일을 파싱하지 못했습니다";


export function createAssetWorkbookSession() {
  // Keep the SheetJS workbook inside the worker; only a size-checked selected sheet crosses back.
  let workbook = null;
  let sheetNames = [];

  function selectSheet(sheet) {
    if (!workbook || !sheetNames.includes(sheet) ||
        !Object.prototype.hasOwnProperty.call(workbook.Sheets, sheet)) {
      throw new Error("선택한 시트를 찾지 못했습니다");
    }
    const { aoa, mergeCount } = unmergeFillWs(workbook.Sheets[sheet]);
    return { sheetNames: sheetNames.slice(), sheet, aoa, mergeCount };
  }

  return {
    open(buffer) {
      workbook = null;
      sheetNames = [];
      const parsed = readWorkbook(buffer);
      workbook = parsed.wb;
      sheetNames = parsed.sheetNames.slice();
      return selectSheet(sheetNames[0]);
    },
    selectSheet,
  };
}


export function handleAssetWorkbookRequest(session, request) {
  const id = request?.id;
  try {
    let result;
    if (request?.type === "open") result = session.open(request.buffer);
    else if (request?.type === "select-sheet") result = session.selectSheet(request.sheet);
    else throw new Error("지원하지 않는 자산 파일 파싱 요청입니다");
    return { id, ok: true, result };
  } catch (error) {
    return { id, ok: false, error: errorMessage(error) };
  }
}

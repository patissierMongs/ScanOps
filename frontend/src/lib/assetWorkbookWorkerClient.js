export const ASSET_WORKBOOK_TIMEOUT_MS = 10_000;


const defaultWorkerFactory = () => new Worker(
  new URL("./assetWorkbook.worker.js", import.meta.url),
  { type: "module" },
);


const timeoutLabel = (timeoutMs) => {
  if (timeoutMs >= 1000 && timeoutMs % 1000 === 0) return `${timeoutMs / 1000}초`;
  return `${timeoutMs}ms`;
};


const transferableBuffer = (value) => {
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  }
  throw new TypeError("자산 파일 데이터가 ArrayBuffer가 아닙니다");
};


export function isCurrentAssetWorkbookSession(session, requestId, parser) {
  return session != null && session.requestId === requestId && session.parser === parser;
}


export function createAssetWorkbookParser({
  workerFactory = defaultWorkerFactory,
  timeoutMs = ASSET_WORKBOOK_TIMEOUT_MS,
} = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("자산 파일 파싱 제한 시간은 양수여야 합니다");
  }

  const worker = workerFactory();
  const pending = new Map();
  let nextId = 1;
  let closed = false;

  const stopWorker = () => {
    try { worker.terminate(); } catch { /* already stopped */ }
  };

  const close = (error) => {
    if (closed) return;
    closed = true;
    stopWorker();
    pending.forEach(({ timer, reject }) => {
      clearTimeout(timer);
      reject(error);
    });
    pending.clear();
  };

  worker.onmessage = (event) => {
    const response = event?.data;
    const request = pending.get(response?.id);
    if (!request) return;
    pending.delete(response.id);
    clearTimeout(request.timer);
    if (response.ok === true) request.resolve(response.result);
    else if (response.ok === false) request.reject(new Error(response.error || "자산 파일을 파싱하지 못했습니다"));
    else {
      const error = new Error("자산 파일 파서가 잘못된 응답을 반환했습니다");
      request.reject(error);
      close(error);
    }
  };

  worker.onerror = (event) => {
    event?.preventDefault?.();
    close(new Error(event?.message || "자산 파일 파서가 비정상 종료되었습니다"));
  };

  const request = (type, payload, transfer = []) => {
    if (closed) return Promise.reject(new Error("자산 파일 파서가 종료되었습니다"));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      // This timer runs on the UI thread, so synchronous SheetJS work cannot postpone termination.
      const timer = setTimeout(() => {
        close(new Error(`자산 파일 파싱 시간 제한(${timeoutLabel(timeoutMs)})을 초과했습니다`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timer });
      try {
        worker.postMessage({ id, type, ...payload }, transfer);
      } catch (error) {
        close(error instanceof Error ? error : new Error("자산 파일 파서에 데이터를 전달하지 못했습니다"));
      }
    });
  };

  return {
    open(value) {
      const buffer = transferableBuffer(value);
      return request("open", { buffer }, [buffer]);
    },
    selectSheet(sheet) {
      return request("select-sheet", { sheet });
    },
    terminate() {
      close(new Error("자산 파일 파서가 종료되었습니다"));
    },
  };
}

import { getToken } from "../api.js";

// 인증 헤더를 붙여 서버 파일을 받아 다운로드(컬럼 내보내기·감사 리포트 등).
export async function downloadFile(path) {
  const headers = {};
  const tok = getToken();
  if (tok) headers.Authorization = "Bearer " + tok;
  const res = await fetch("/api" + path, { headers });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: "내보내기 실패" }));
    throw new Error(e.detail || "내보내기 실패");
  }
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const m = /filename=([^;]+)/.exec(cd);
  triggerBlob(blob, m ? m[1].trim().replace(/"/g, "") : "download");
}

// 클라이언트 생성 텍스트를 다운로드(부서 통보문 .txt 등). UTF-8 BOM 선두.
export function downloadText(text, name, withBom = true) {
  const blob = new Blob([(withBom ? "﻿" : "") + text], { type: "text/plain;charset=utf-8" });
  triggerBlob(blob, name);
}

function triggerBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const TOKEN_KEY = "scanops_token";

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

export async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  const tok = getToken();
  if (tok) headers.Authorization = "Bearer " + tok;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    opts = { ...opts, body: JSON.stringify(opts.json) };
  }
  const res = await fetch("/api" + path, { ...opts, headers });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    // 상태 코드를 남긴다 — '이미 있음(409)'과 '권한 없음(403)'을 호출부가 구분해야 할 때가 있다.
    throw Object.assign(new Error(e.detail || "요청 실패"), { status: res.status });
  }
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return res;
  const body = await res.json();
  // raw:true 는 본문과 함께 전체 건수를 돌려준다(페이지 목록에서 '몇 건 중 몇 건'을 보여주려면 필요).
  if (!opts.raw) return body;
  const total = Number(res.headers.get("X-Total-Count"));
  // 서버가 접은 건수도 함께 싣는다. 화면이 이 값을 말하지 않으면 열린 포트가 조용히 사라진다.
  const num = (name) => { const v = Number(res.headers.get(name)); return Number.isFinite(v) ? v : 0; };
  const hidden = { unconfirmed: num("X-Hidden-Unconfirmed"), tcpwrapped: num("X-Hidden-Tcpwrapped") };
  return {
    body, hidden,
    total: Number.isFinite(total) ? total : (Array.isArray(body) ? body.length : 0),
  };
}

export async function upload(path, file) {
  const fd = new FormData();
  fd.append("file", file);
  const headers = {};
  const tok = getToken();
  if (tok) headers.Authorization = "Bearer " + tok;
  const res = await fetch("/api" + path, { method: "POST", body: fd, headers });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(e.detail || "업로드 실패");
  }
  return res.json();
}

export async function uploadMany(path, files) {
  const fd = new FormData();
  files.forEach((entry) => {
    const file = entry.file || entry;
    const name = entry.name || file.webkitRelativePath || file.name;
    fd.append("files", file, name);
  });
  const headers = {};
  const tok = getToken();
  if (tok) headers.Authorization = "Bearer " + tok;
  const res = await fetch("/api" + path, { method: "POST", body: fd, headers });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(e.detail || "업로드 실패");
  }
  return res.json();
}

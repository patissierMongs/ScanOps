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
  return ct.includes("application/json") ? res.json() : res;
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

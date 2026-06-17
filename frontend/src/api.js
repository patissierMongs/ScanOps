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
    throw new Error(e.detail || "요청 실패");
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

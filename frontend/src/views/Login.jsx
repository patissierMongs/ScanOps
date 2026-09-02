import React, { useEffect, useState } from "react";
import { api, setToken } from "../api.js";
import "./login.css";

// 레이더 블립 좌표(데코) — 스윕이 지나갈 때 탐지된 듯 점멸.
const BLIPS = [
  { cls: "", top: "30%", left: "62%", delay: "0.6s" },
  { cls: "a", top: "58%", left: "70%", delay: "1.9s" },
  { cls: "r", top: "44%", left: "78%", delay: "3.1s" },
  { cls: "", top: "68%", left: "52%", delay: "2.5s" },
  { cls: "", top: "38%", left: "44%", delay: "3.8s" },
];

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    let live = true;
    fetch("/api/health", { headers: { Accept: "application/json" } })
      .then((r) => r.json().then((body) => ({ ok: r.ok, ...body })))
      .then((h) => { if (live) setHealth(h); })
      .catch(() => { if (live) setHealth({ ok: false, ready: false, version: "", errors: ["unreachable"] }); });
    return () => { live = false; };
  }, []);
  const state = health === null ? "…" : health.ready ? "READY" : "NOT READY";
  const version = health?.version ? `v${health.version}` : "";

  function submit(e) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    api("/auth/login", { method: "POST", json: { username, password } })
      .then((r) => {
        setToken(r.token);
        return api("/auth/me");
      })
      .then(onLogin)
      .catch((e2) => setErr(e2.message || "인증 실패"))
      .finally(() => setBusy(false));
  }

  return (
    <div className="lg-root">
      <div className="lg-grain" />
      <div className="lg-stage">
        {/* ── 히어로: 레이더 스캔 콘솔 ── */}
        <aside className="lg-hero">
          <span className="lg-tick tl" />
          <span className="lg-tick bl" />
          <div className="lg-radar" aria-hidden="true">
            <div className="lg-rings" />
            <div className="lg-cross" />
            <div className="lg-sweep" />
            <div className="lg-scanline" />
            {BLIPS.map((b, i) => (
              <span key={i} className={"lg-blip " + b.cls} style={{ top: b.top, left: b.left, animationDelay: b.delay }} />
            ))}
            <div className="lg-core" />
          </div>
          <div className="lg-hud">
            <div className="lg-hud-row"><span className="k">기준</span><b>KISA · NIS</b><span className="bar" /></div>
            <div className="lg-hud-row"><span className="k">서버</span><b>{state}</b><span className="bar" /></div>
            {health && !health.ready && health.errors?.length > 0 && (
              <div className="lg-hud-row"><span className="k">사유</span><b>{health.errors.join(", ")}</b><span className="bar" /></div>
            )}
          </div>
        </aside>

        {/* ── 인증 패널 ── */}
        <main className="lg-panel">
          <div className="lg-brand">
            <span className="lg-dots"><i /><i /><i /></span>
            <span className="lg-word">Scan<b>Ops</b></span>
          </div>
          <div className="lg-tagline">네트워크 노출 점검 운영 콘솔</div>
          <div className="lg-rule" />

          <form className="lg-form" onSubmit={submit}>
            <label className="lg-field">
              <span className="lg-label">Operator · 운영자</span>
              <div className="lg-input">
                <span className="lg-prompt">›</span>
                <input autoFocus autoComplete="username" placeholder="아이디"
                       value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
            </label>
            <label className="lg-field">
              <span className="lg-label">Passphrase · 비밀번호</span>
              <div className="lg-input">
                <span className="lg-prompt">›</span>
                <input type="password" autoComplete="current-password" placeholder="••••••••"
                       value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            </label>

            {err && <div className="lg-err">{err}</div>}

            <button className={"lg-go" + (busy ? " busy" : "")} disabled={busy || !username || !password}>
              <span>{busy ? "인증 중" : "접속"}</span>
              {!busy && <span className="ar">→</span>}
            </button>
          </form>

          <div className="lg-foot">
            <span className="lg-stat"><span className={"lg-led" + (health && !health.ready ? " off" : "")} /> {state === "…" ? "확인 중" : state === "READY" ? "서버 준비됨" : "서버 준비 안 됨"}</span>
            <span>{version}</span>
          </div>
        </main>
      </div>
    </div>
  );
}

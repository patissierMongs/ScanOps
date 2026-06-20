import React, { useEffect, useState } from "react";
import { api, clearToken, getToken } from "./api.js";
import ErrorBoundary from "./app/ErrorBoundary.jsx";
import { ToastProvider, useToast } from "./ui/Toast.jsx";
import PasswordModal from "./ui/PasswordModal.jsx";
import Login from "./views/Login.jsx";
import Dashboard from "./views/Dashboard.jsx";
import Findings from "./views/Findings.jsx";
import Rules from "./views/Rules.jsx";
import History from "./views/History.jsx";
import Timeline from "./views/Timeline.jsx";
import Assets from "./views/Assets.jsx";
import Notifications from "./views/Notifications.jsx";
import Scans from "./views/Scans.jsx";
import Users from "./views/Users.jsx";

const NAV = [
  { k: "dashboard", label: "대시보드", ico: "▦" },
  { k: "findings", label: "발견 관리", ico: "⚑", badge: "open" },
  { k: "rules", label: "위험 규칙", ico: "⚠" },
  { k: "history", label: "이력", ico: "↻" },
  { k: "timeline", label: "시간축", ico: "▥" },
  { k: "assets", label: "자산대장", ico: "▤" },
  { k: "notify", label: "부서통보", ico: "✉" },
  { k: "scans", label: "스캔", ico: "◎" },
  { k: "users", label: "사용자", ico: "◍", admin: true },
];

const TITLES = {
  dashboard: "대시보드", findings: "발견 관리", rules: "위험 규칙", history: "변경 이력",
  timeline: "시간축 히트맵", assets: "자산대장", notify: "부서통보", scans: "스캔", users: "사용자 관리",
};

export default function App() {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) {
      setReady(true);
      return;
    }
    api("/auth/me")
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setReady(true));
  }, []);

  if (!ready) return null;
  return (
    <ToastProvider>
      {user ? (
        <Shell user={user} onLogout={() => { clearToken(); setUser(null); }} />
      ) : (
        <Login onLogin={setUser} />
      )}
    </ToastProvider>
  );
}

function Shell({ user, onLogout }) {
  const [view, setView] = useState("dashboard");
  const [openCount, setOpenCount] = useState(null);
  const [pwOpen, setPwOpen] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let live = true;
    api("/dashboard")
      .then((d) => { if (live) setOpenCount(d.open_total); })
      .catch(() => {});
    return () => { live = false; };
  }, [view]);

  const isAdmin = user.role === "admin";
  const nav = NAV.filter((n) => !n.admin || isAdmin);

  const views = {
    dashboard: <Dashboard onNav={setView} />,
    findings: <Findings user={user} />,
    rules: <Rules user={user} />,
    history: <History />,
    timeline: <Timeline />,
    assets: <Assets user={user} />,
    notify: <Notifications user={user} />,
    scans: <Scans user={user} />,
    users: <Users user={user} />,
  };

  return (
    <div className="app">
      <div className="sidebar">
        <div className="brand">
          <span className="dots">
            <span style={{ background: "oklch(0.72 0.16 25)" }} />
            <span style={{ background: "oklch(0.82 0.13 85)" }} />
            <span style={{ background: "oklch(0.78 0.14 145)" }} />
          </span>
          <h1>ScanOps</h1>
        </div>
        <div className="brand sub">노출 점검 운영</div>
        <nav className="nav">
          {nav.map((n) => (
            <a key={n.k} className={view === n.k ? "active" : ""} onClick={() => setView(n.k)}>
              <span className="ico">{n.ico}</span>
              {n.label}
              {n.badge === "open" && openCount != null && <span className="badge">{openCount}</span>}
            </a>
          ))}
        </nav>
        <div className="who">
          <b>{user.display_name}</b> · {user.role}
          <br />
          <a onClick={() => setPwOpen(true)}>비밀번호 변경</a> · <a onClick={onLogout}>로그아웃</a>
        </div>
      </div>
      {pwOpen && (
        <PasswordModal
          title="비밀번호 변경"
          requireCurrent
          onClose={() => setPwOpen(false)}
          onSubmit={({ current, next }) =>
            api("/auth/change-password", {
              method: "POST",
              json: { current_password: current, new_password: next },
            })
              .then(() => toast("비밀번호가 변경되었습니다."))
              .catch((e) => { toast(e.message, { type: "err" }); throw e; })
          }
        />
      )}
      <div className="main">
        <div className="topbar">
          <h2>{TITLES[view]}</h2>
          <div className="spacer" />
        </div>
        <ErrorBoundary key={view}>{views[view]}</ErrorBoundary>
      </div>
    </div>
  );
}

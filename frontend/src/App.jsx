import React, { useEffect, useRef, useState } from "react";
import { api, clearToken, getToken } from "./api.js";
import ErrorBoundary from "./app/ErrorBoundary.jsx";
import { ToastProvider, useToast } from "./ui/Toast.jsx";
import PasswordModal from "./ui/PasswordModal.jsx";
import Login from "./views/Login.jsx";
import Dashboard from "./views/Dashboard.jsx";
import Findings from "./views/Findings.jsx";
import Heatmap from "./views/Heatmap.jsx";
import Rules from "./views/Rules.jsx";
import History from "./views/History.jsx";
import Assets from "./views/Assets.jsx";
import Notifications from "./views/Notifications.jsx";
import Scans from "./views/Scans.jsx";
import Users from "./views/Users.jsx";

const NAV = [
  { k: "dashboard", label: "대시보드", ico: "▦" },
  { k: "findings", label: "발견 관리", ico: "⚑", badge: "open" },
  { k: "heatmap", label: "히트맵", ico: "▥" },
  { k: "rules", label: "규칙", ico: "⚠" },
  { k: "history", label: "이력", ico: "↻" },
  { k: "assets", label: "자산대장", ico: "▤" },
  { k: "notify", label: "부서통보", ico: "✉" },
  { k: "scans", label: "스캔", ico: "◎" },
  { k: "users", label: "사용자", ico: "◍", admin: true },
];

const TITLES = {
  dashboard: "대시보드", findings: "발견 관리", rules: "규칙", history: "변경 이력",
  heatmap: "시간축 히트맵", assets: "자산대장", notify: "부서통보", scans: "스캔", users: "사용자 관리",
};

const MOBILE_NAV_QUERY = "(max-width: 760px)";

function setInert(node, value) {
  if (!node) return;
  node.inert = value;
  if (value) node.setAttribute("inert", "");
  else node.removeAttribute("inert");
}

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
  const [navOpen, setNavOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(() =>
    typeof window !== "undefined" && window.matchMedia(MOBILE_NAV_QUERY).matches
  );
  const sidebarRef = useRef(null);
  const mainRef = useRef(null);
  const navRestoreFocusRef = useRef(null);
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
    dashboard: <Dashboard onNav={(next) => { setView(next); setNavOpen(false); }} />,
    findings: <Findings user={user} />,
    heatmap: <Heatmap />,
    rules: <Rules user={user} />,
    history: <History />,
    assets: <Assets user={user} />,
    notify: <Notifications user={user} />,
    scans: <Scans user={user} />,
    users: <Users user={user} />,
  };

  useEffect(() => {
    const media = window.matchMedia(MOBILE_NAV_QUERY);
    const update = () => {
      setMobileNav(media.matches);
      if (!media.matches) setNavOpen(false);
    };
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, []);

  useEffect(() => {
    const sidebar = sidebarRef.current;
    const main = mainRef.current;
    if (!mobileNav) {
      setInert(sidebar, false);
      setInert(main, false);
      return;
    }

    setInert(sidebar, !navOpen);
    setInert(main, navOpen);
    if (!navOpen) return;

    sidebar?.querySelector("button:not([disabled])")?.focus();
    function onKey(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        setNavOpen(false);
        return;
      }
      if (event.key !== "Tab" || !sidebar) return;
      const focusable = [...sidebar.querySelectorAll(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )];
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      setInert(main, false);
      const restore = navRestoreFocusRef.current;
      navRestoreFocusRef.current = null;
      if (restore?.isConnected) restore.focus();
    };
  }, [mobileNav, navOpen]);

  function openNav(event) {
    navRestoreFocusRef.current = event?.currentTarget || document.activeElement;
    setNavOpen(true);
  }

  function selectView(next) {
    setView(next);
    setNavOpen(false);
  }

  function openPassword() {
    setNavOpen(false);
    setPwOpen(true);
  }

  return (
    <>
    <div className="app" data-app-shell>
      {navOpen && <button className="nav-scrim" aria-label="탐색 메뉴 닫기" onClick={() => setNavOpen(false)} />}
      <aside id="primary-navigation" ref={sidebarRef} className={`sidebar ${navOpen ? "open" : ""}`}
             aria-label="주 탐색" aria-hidden={mobileNav && !navOpen ? "true" : undefined}
             role={mobileNav ? "dialog" : undefined} aria-modal={mobileNav && navOpen ? "true" : undefined}>
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
            <button key={n.k} type="button" className={view === n.k ? "active" : ""}
                    aria-current={view === n.k ? "page" : undefined} onClick={() => selectView(n.k)}>
              <span className="ico">{n.ico}</span>
              {n.label}
              {n.badge === "open" && openCount != null && <span className="badge">{openCount}</span>}
            </button>
          ))}
        </nav>
        <div className="who">
          <b>{user.display_name}</b> · {user.role}
          <br />
          <button type="button" className="account-action" onClick={openPassword}>비밀번호 변경</button>
          <span aria-hidden="true"> · </span>
          <button type="button" className="account-action" onClick={onLogout}>로그아웃</button>
        </div>
      </aside>
      <div ref={mainRef} className="main">
        <div className="topbar">
          <button type="button" className="menu-toggle" aria-label="탐색 메뉴 열기"
                  aria-controls="primary-navigation" aria-expanded={navOpen} onClick={openNav}>☰</button>
          <h2>{TITLES[view]}</h2>
          <div className="spacer" />
        </div>
        <ErrorBoundary key={view}>{views[view]}</ErrorBoundary>
      </div>
    </div>
    {pwOpen && (
      <PasswordModal
        title="비밀번호 변경"
        requireCurrent
        onClose={() => setPwOpen(false)}
        onSuccess={onLogout}
        onSubmit={({ current, next }) =>
          api("/auth/change-password", {
            method: "POST",
            json: { current_password: current, new_password: next },
          })
            .then(() => toast("비밀번호가 변경되었습니다. 다시 로그인해 주세요."))
            .catch((e) => { toast(e.message, { type: "err" }); throw e; })
        }
      />
    )}
    </>
  );
}

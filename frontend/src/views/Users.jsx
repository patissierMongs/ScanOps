import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import PasswordModal from "../ui/PasswordModal.jsx";

const ROLES = ["viewer", "auditor", "admin"];

export default function Users() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer", display_name: "" });
  const [resetFor, setResetFor] = useState(null);
  const toast = useToast();

  function load() {
    api("/users").then(setUsers).catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, []);

  function create(e) {
    e.preventDefault();
    api("/users", { method: "POST", json: form })
      .then(() => {
        toast("사용자 생성됨");
        setForm({ username: "", password: "", role: "viewer", display_name: "" });
        load();
      })
      .catch((e2) => toast(e2.message, { type: "err" }));
  }

  return (
    <div className="content">
      <div className="panel">
        <h3>새 사용자</h3>
        <form className="row" onSubmit={create}>
          <input placeholder="아이디" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input placeholder="이름" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
          <input type="password" placeholder="비밀번호" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="primary" disabled={!form.username || !form.password}>생성</button>
        </form>
      </div>

      <div className="panel">
        <h3>사용자 목록</h3>
        <table className="tbl">
          <thead><tr><th>ID</th><th>아이디</th><th>이름</th><th>역할</th><th>활성</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td className="mono">{u.id}</td><td>{u.username}</td>
                <td>{u.display_name}</td><td>{u.role}</td>
                <td>{u.is_active ? "✓" : "—"}</td>
                <td><button className="sm" onClick={() => setResetFor(u)}>비밀번호 재설정</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {resetFor && (
        <PasswordModal
          title={`비밀번호 재설정 — ${resetFor.username}`}
          onClose={() => setResetFor(null)}
          onSubmit={({ next }) =>
            api(`/users/${resetFor.id}/reset-password`, { method: "POST", json: { new_password: next } })
              .then(() => toast(`${resetFor.username} 비밀번호가 재설정되었습니다.`))
              .catch((e) => { toast(e.message, { type: "err" }); throw e; })
          }
        />
      )}
    </div>
  );
}

import React, { useState } from "react";

// 비밀번호 설정 모달. requireCurrent=true 면 현재 비밀번호 입력(본인 변경),
// 아니면 새 비밀번호만(admin 재설정). onSubmit({current,next}) 은 Promise 반환:
// 성공(resolve) 시 닫히고, 실패(reject) 시 유지(부모가 토스트).
export default function PasswordModal({ title, requireCurrent = false, onSubmit, onClose }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const tooShort = next.length > 0 && next.length < 8;
  const mismatch = confirm.length > 0 && confirm !== next;
  const invalid = (requireCurrent && !current) || next.length < 8 || confirm !== next;

  function submit(e) {
    e.preventDefault();
    if (invalid || busy) return;
    setBusy(true);
    Promise.resolve(onSubmit({ current, next }))
      .then(() => onClose())
      .catch(() => setBusy(false)); // 실패 시 모달 유지
  }

  return (
    <div className="modal" onClick={onClose}>
      <form className="panel modal-card" onClick={(e) => e.stopPropagation()} onSubmit={submit}>
        <h3>{title}</h3>
        {requireCurrent && (
          <input
            type="password" placeholder="현재 비밀번호" value={current} autoFocus
            onChange={(e) => setCurrent(e.target.value)}
          />
        )}
        <input
          type="password" placeholder="새 비밀번호 (8자 이상)" value={next} autoFocus={!requireCurrent}
          onChange={(e) => setNext(e.target.value)}
        />
        <input
          type="password" placeholder="새 비밀번호 확인" value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {tooShort && <span className="err">새 비밀번호는 8자 이상이어야 합니다.</span>}
        {mismatch && <span className="err">새 비밀번호가 일치하지 않습니다.</span>}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 2 }}>
          <button type="button" className="sm" onClick={onClose}>취소</button>
          <button type="submit" className="primary" disabled={invalid || busy}>변경</button>
        </div>
      </form>
    </div>
  );
}

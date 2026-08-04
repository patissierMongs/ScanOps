import React, { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

// 비밀번호 설정 모달. requireCurrent=true 면 현재 비밀번호 입력(본인 변경),
// 아니면 새 비밀번호만(admin 재설정). onSubmit({current,next}) 은 Promise 반환:
// 성공(resolve) 시 닫히고, 실패(reject) 시 유지(부모가 토스트).
export default function PasswordModal({ title, requireCurrent = false, onSubmit, onClose, onSuccess }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const titleId = useId();
  const currentId = useId();
  const nextId = useId();
  const confirmId = useId();
  const errorId = useId();
  const dialogRef = useRef(null);
  const onCloseRef = useRef(onClose);
  const onSuccessRef = useRef(onSuccess);
  onCloseRef.current = onClose;
  onSuccessRef.current = onSuccess;

  const tooShort = next.length > 0 && next.length < 8;
  const mismatch = confirm.length > 0 && confirm !== next;
  const invalid = (requireCurrent && !current) || next.length < 8 || confirm !== next;

  function submit(e) {
    e.preventDefault();
    if (invalid || busy) return;
    setBusy(true);
    Promise.resolve(onSubmit({ current, next }))
      .then(() => {
        onCloseRef.current();
        onSuccessRef.current?.();
      })
      .catch(() => setBusy(false)); // 실패 시 모달 유지
  }

  function onDialogKeyDown(event) {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopPropagation();
    onCloseRef.current();
  }

  useEffect(() => {
    const previous = document.activeElement;
    const shell = document.querySelector("[data-app-shell]");
    if (shell) {
      shell.inert = true;
      shell.setAttribute("inert", "");
    }
    const first = dialogRef.current?.querySelector("input");
    first?.focus();

    function onKey(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = [...dialogRef.current.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )];
      if (!focusable.length) return;
      const firstEl = focusable[0], lastEl = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === firstEl) {
        event.preventDefault(); lastEl.focus();
      } else if (!event.shiftKey && document.activeElement === lastEl) {
        event.preventDefault(); firstEl.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (shell) {
        shell.inert = false;
        shell.removeAttribute("inert");
      }
      if (previous?.isConnected) previous.focus();
    };
  }, []);

  return createPortal(
    <div className="modal" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <form ref={dialogRef} className="panel modal-card" onSubmit={submit} onKeyDown={onDialogKeyDown}
            role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <h3 id={titleId}>{title}</h3>
        {requireCurrent && (
          <label className="field" htmlFor={currentId}>현재 비밀번호
          <input id={currentId}
            type="password" placeholder="현재 비밀번호" value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
          />
          </label>
        )}
        <label className="field" htmlFor={nextId}>새 비밀번호
        <input id={nextId}
          type="password" placeholder="새 비밀번호 (8자 이상)" value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password" aria-invalid={tooShort || undefined}
          aria-describedby={tooShort || mismatch ? errorId : undefined}
        />
        </label>
        <label className="field" htmlFor={confirmId}>새 비밀번호 확인
        <input id={confirmId}
          type="password" placeholder="새 비밀번호 확인" value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password" aria-invalid={mismatch || undefined}
          aria-describedby={mismatch ? errorId : undefined}
        />
        </label>
        {(tooShort || mismatch) && (
          <span id={errorId} className="err">
            {tooShort ? "새 비밀번호는 8자 이상이어야 합니다." : "새 비밀번호가 일치하지 않습니다."}
          </span>
        )}
        <div className="row" style={{ justifyContent: "flex-end", marginTop: 2 }}>
          <button type="button" className="sm" onClick={onClose}>취소</button>
          <button type="submit" className="primary" disabled={invalid || busy}>변경</button>
        </div>
      </form>
    </div>,
    document.body,
  );
}

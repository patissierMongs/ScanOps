import React, { createContext, useCallback, useContext, useRef, useState } from "react";
import { toastAnnouncement, toastDuration } from "../lib/toast.js";

// 토스트 + 되돌리기(undo) 패턴. push(msg, {type, action:{label,onClick}, timeout}).
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

let _id = 0;

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const timers = useRef({});

  const remove = useCallback((id) => {
    setItems((xs) => xs.filter((t) => t.id !== id));
    if (timers.current[id]) {
      clearTimeout(timers.current[id]);
      delete timers.current[id];
    }
  }, []);

  const push = useCallback(
    (msg, opts = {}) => {
      const id = ++_id;
      const timeout = toastDuration(opts);
      setItems((xs) => [...xs, { id, msg, type: opts.type || "", action: opts.action || null }]);
      timers.current[id] = setTimeout(() => remove(id), timeout);
      return id;
    },
    [remove],
  );

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-label="알림">
        {items.map((t) => {
          const announcement = toastAnnouncement(t.type);
          return (
          <div key={t.id} className={"toast " + t.type}
               role={announcement.role} aria-live={announcement.live} aria-atomic="true">
            <span>{t.msg}</span>
            {t.action && (
              <button
                className="sm"
                style={{ marginLeft: 12, background: "transparent", color: "#fff", borderColor: "rgba(255,255,255,.4)" }}
                onClick={() => {
                  t.action.onClick();
                  remove(t.id);
                }}
              >
                {t.action.label}
              </button>
            )}
          </div>
          );
        })}
      </div>
    </ToastCtx.Provider>
  );
}

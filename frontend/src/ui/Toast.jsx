import React, { createContext, useCallback, useContext, useRef, useState } from "react";

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
      const timeout = opts.timeout ?? (opts.action ? 6000 : 3000);
      setItems((xs) => [...xs, { id, msg, type: opts.type || "", action: opts.action || null }]);
      timers.current[id] = setTimeout(() => remove(id), timeout);
      return id;
    },
    [remove],
  );

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">
        {items.map((t) => (
          <div key={t.id} className={"toast " + t.type}>
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
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

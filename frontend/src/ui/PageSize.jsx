import React from "react";

import { PAGE_SIZES } from "../lib/pageSize.js";

export { PAGE_SIZES };

export default function PageSize({ value, onChange, label = "한 페이지" }) {
  return (
    <label className="row" style={{ gap: 5 }} title="한 화면에 표시할 건수">
      <span className="muted" style={{ fontSize: 12 }}>{label}</span>
      <select value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {PAGE_SIZES.map((n) => (
          <option key={n} value={n}>{n.toLocaleString()}건</option>
        ))}
      </select>
    </label>
  );
}

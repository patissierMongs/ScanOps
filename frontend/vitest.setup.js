// Testing Library 의 DOM 매처(toBeInTheDocument 등)를 vitest expect 에 등록.
import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// globals:false 라 RTL 자동 cleanup 이 안 걸리므로 매 테스트 후 수동 언마운트(렌더 누적 방지).
afterEach(() => cleanup());

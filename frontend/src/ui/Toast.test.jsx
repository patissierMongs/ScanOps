import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ToastProvider, useToast } from "./Toast.jsx";

// useToast 를 소비하는 최소 하네스 — push(메시지, {action}) 흐름을 실제 렌더로 검증.
function Harness({ onUndo }) {
  const push = useToast();
  return (
    <button onClick={() => push("저장되었습니다", { action: { label: "되돌리기", onClick: onUndo } })}>
      저장
    </button>
  );
}

describe("ToastProvider / useToast", () => {
  it("push 하면 토스트 메시지가 렌더된다", async () => {
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <Harness onUndo={() => {}} />
      </ToastProvider>,
    );
    expect(screen.queryByText("저장되었습니다")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "저장" }));
    expect(screen.getByText("저장되었습니다")).toBeInTheDocument();
  });

  it("되돌리기 버튼은 action.onClick 을 호출하고 토스트를 닫는다", async () => {
    const user = userEvent.setup();
    const onUndo = vi.fn();
    render(
      <ToastProvider>
        <Harness onUndo={onUndo} />
      </ToastProvider>,
    );
    await user.click(screen.getByRole("button", { name: "저장" }));
    await user.click(screen.getByRole("button", { name: "되돌리기" }));
    expect(onUndo).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("저장되었습니다")).not.toBeInTheDocument();
  });
});

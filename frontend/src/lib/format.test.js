import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { asDate, dday, RISK_LABEL, riskClass, STATUS_CLASS } from "./format.js";

// today() 는 new Date() 를 쓰므로 시스템 시각을 고정해 D-day 를 결정적으로 검증한다.
// (dday 내부의 new Date("YYYY-MM-DD") 는 인자 있는 생성이라 fake timer 영향을 받지 않는다.)
describe("dday", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-01T12:00:00Z")); // today = 2026-07-01 (UTC 기준)
  });
  afterEach(() => vi.useRealTimers());

  it("마감이 없으면 none", () => {
    expect(dday("")).toEqual({ text: "—", cls: "none", over: false });
    expect(dday(null)).toEqual({ text: "—", cls: "none", over: false });
  });

  it("지난 마감은 초과(over)", () => {
    const r = dday("2026-06-29"); // 2일 전
    expect(r).toEqual({ text: "2일 초과", cls: "over", over: true });
  });

  it("오늘 마감은 near/오늘", () => {
    expect(dday("2026-07-01")).toEqual({ text: "오늘", cls: "near", over: false });
  });

  it("3일 이내는 near, 그 이후는 ok", () => {
    expect(dday("2026-07-03").cls).toBe("near"); // D-2
    expect(dday("2026-07-04")).toEqual({ text: "D-3", cls: "near", over: false });
    expect(dday("2026-07-06")).toEqual({ text: "D-5", cls: "ok", over: false });
  });

  it("ISO 타임스탬프도 날짜부만 본다", () => {
    expect(dday("2026-07-05T23:59:59Z").text).toBe("D-4");
  });
});

describe("asDate", () => {
  it("앞 10자(YYYY-MM-DD)만 남기고 빈값은 빈 문자열", () => {
    expect(asDate("2026-07-01T10:20:30Z")).toBe("2026-07-01");
    expect(asDate("")).toBe("");
    expect(asDate(null)).toBe("");
  });
});

describe("riskClass / RISK_LABEL", () => {
  it("알려진 등급은 그대로, 모르는 값은 info 로 정규화", () => {
    expect(riskClass("high")).toBe("high");
    expect(riskClass("banned")).toBe("banned");
    expect(riskClass("weird")).toBe("info");
    expect(riskClass(undefined)).toBe("info");
  });

  it("등급 라벨은 한국어", () => {
    expect(RISK_LABEL.high).toBe("상");
    expect(RISK_LABEL.banned).toBe("금지");
    expect(STATUS_CLASS["미조치"]).toBe("high");
  });
});

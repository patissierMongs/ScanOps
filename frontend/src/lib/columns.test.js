import { describe, expect, it } from "vitest";

import {
  ALL_COLUMNS,
  cellValue,
  COLUMN_MAP,
  DEFAULT_PRESET_ID,
  PRESETS,
  prettyFingerprint,
} from "./columns.js";

describe("prettyFingerprint", () => {
  it("빈 입력은 빈 문자열", () => {
    expect(prettyFingerprint("")).toBe("");
    expect(prettyFingerprint(null)).toBe("");
  });

  it("probe 그룹 헤더를 [..] 로 감싸고 같은 응답은 합친다", () => {
    const raw = "  GetRequest:\n    HTTP/1.0 200 OK\n  HTTPOptions:\n    HTTP/1.0 200 OK";
    // 두 probe 가 동일 응답 → 첫 그룹만 남고 중복 제거.
    expect(prettyFingerprint(raw)).toBe("[GetRequest]\nHTTP/1.0 200 OK");
  });

  it("서로 다른 응답은 빈 줄로 구분해 모두 보존", () => {
    const raw = "  A:\n    one\n  B:\n    two";
    expect(prettyFingerprint(raw)).toBe("[A]\none\n\n[B]\ntwo");
  });
});

describe("cellValue", () => {
  const finding = {
    host_ip: "10.0.0.1",
    port: 443,
    risk_level: "high",
    status: "미조치",
    reopened: 1,
    compliance_json: [
      { std: "ISMS", ref: "2.1" },
      { std: "PCI", ref: "1.2" },
    ],
  };

  it("단순 필드는 값을 그대로 반환", () => {
    expect(cellValue(finding, "host_ip")).toBe("10.0.0.1");
    expect(cellValue(finding, "port")).toBe(443);
  });

  it("위험등급은 한국어 라벨로 변환", () => {
    expect(cellValue(finding, "risk_level")).toBe("상");
  });

  it("컴플라이언스 근거는 std:ref 를 '; ' 로 결합", () => {
    expect(cellValue(finding, "compliance")).toBe("ISMS:2.1; PCI:1.2");
  });

  it("재발 태그는 truthy 면 '재발', 아니면 빈값", () => {
    expect(cellValue(finding, "reopened")).toBe("재발");
    expect(cellValue({ ...finding, reopened: 0 }, "reopened")).toBe("");
  });

  it("알 수 없는 key 는 빈 문자열", () => {
    expect(cellValue(finding, "nope")).toBe("");
  });

  it("null 필드는 빈 문자열로 폴백(?? '')", () => {
    expect(cellValue({}, "host_ip")).toBe("");
  });
});

describe("PRESETS / COLUMN_MAP 정합성", () => {
  it("모든 프리셋 컬럼 key 는 COLUMN_MAP 에 존재", () => {
    for (const preset of PRESETS) {
      for (const key of preset.cols) {
        expect(COLUMN_MAP, `${preset.id} → ${key}`).toHaveProperty(key);
      }
    }
  });

  it("기본 프리셋 ID 는 실제 프리셋을 가리킨다", () => {
    expect(PRESETS.some((p) => p.id === DEFAULT_PRESET_ID)).toBe(true);
  });

  it("COLUMN_MAP 은 ALL_COLUMNS 를 key 로 색인한다", () => {
    expect(Object.keys(COLUMN_MAP)).toHaveLength(ALL_COLUMNS.length);
    for (const col of ALL_COLUMNS) {
      expect(COLUMN_MAP[col.key]).toBe(col);
    }
  });
});

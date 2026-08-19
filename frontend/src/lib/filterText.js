// 필터 문법 한 곳 — 화면마다 규칙이 다르면 외울 수 없다.
//
// `!` 로 시작하면 제외다. 목록에서 몇 건을 빼고 보는 일이 훨씬 잦은데 그동안 '아닌 것'을
// 표현할 방법이 없어 눈으로 걸러야 했다. `!!` 는 문자 그대로의 `!` — 제외를 도입하면서
// `!` 로 시작하는 값 자체를 검색할 길이 막히면 안 된다.
//
// 서버(backend/scanops/api/findings.py 의 parse_needle)와 같은 규칙이다. 클라이언트에서만
// 거르는 화면(자산대장)도 같은 문법을 쓰게 해서, 사용자가 화면마다 다시 배우지 않게 한다.
export const NEGATE = "!";

export function parseNeedle(text) {
  const raw = String(text ?? "");
  if (raw.startsWith(NEGATE + NEGATE)) return { needle: raw.slice(1), negate: false };
  if (raw.startsWith(NEGATE)) return { needle: raw.slice(1), negate: true };
  return { needle: raw, negate: false };
}

// values 중 하나라도 맞으면 통과. 제외면 뒤집는다 — '어느 한 값에만 없으면 통과'로 읽으면
// 사실상 아무것도 걸러지지 않는다.
export function matchesFilter(values, text) {
  const { needle, negate } = parseNeedle(String(text ?? "").trim().toLowerCase());
  if (!needle) return true;
  const hit = values.some((v) => String(v ?? "").toLowerCase().includes(needle));
  return hit !== negate;
}

export const FILTER_HINT = "! 로 시작하면 제외 (예: !ssh). !! 는 문자 그대로의 !";

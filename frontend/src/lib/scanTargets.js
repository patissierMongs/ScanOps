export function splitScanTokens(value) {
  return [...new Set(String(value || "").split(/[\s,]+/).map((token) => token.trim()).filter(Boolean))];
}

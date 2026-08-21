export function formatScanPortScope(summary) {
  let ports = String(summary?.ports || "—").replace(/\s*\(일부 제외\)\s*$/, "");
  const protocols = summary?.protocols || [];
  const alreadyNamesProtocol = /(?:^|·)\s*(?:TCP|UDP)\b/.test(ports);

  if (protocols.length && !alreadyNamesProtocol) {
    ports = `${protocols.join("·")} ${ports}`;
  }

  const excluded = String(summary?.excluded_ports || "").trim();
  return excluded ? `${ports}: ${excluded} 제외` : ports;
}

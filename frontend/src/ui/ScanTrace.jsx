import React from "react";

/**
 * 실행 추적 패널 — "어디서 지연이 생기는가"에 답하는 자리.
 *
 * 진행률 하나로는 몇 시간짜리 스캔에서 무엇이 시간을 쓰는지 알 수 없었다. 단계 요약도
 * 합계만 말하므로 마찬가지다. 지연의 실제 단위는 nmap 프로세스 하나이고, 엔진이 그
 * 단위로 시작·종료·수확량·nmap 내부 단계 체류시간을 적어 준다. 여기서는 그것을 네 갈래로
 * 보여준다 — 지금 도는 것 / 단계별 / nmap 내부 단계별 / 가장 오래 걸린 실행.
 *
 * 평소에는 접어 둔다. 진단이 필요할 때만 펼치는 정보라, 늘 펼쳐 두면 정작 상태를 읽어야
 * 하는 표를 밀어낸다. <details> 를 쓰므로 열림 여부는 브라우저가 알아서 기억한다.
 */

export function fmtSeconds(sec) {
  if (sec == null) return "—";
  if (sec < 1) return "<1초";
  if (sec < 60) return `${Math.round(sec)}초`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  if (m < 60) return s ? `${m}분 ${s}초` : `${m}분`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return mm ? `${h}시간 ${mm}분` : `${h}시간`;
}

const STAGE_LABEL = {
  discovery: "호스트 발견", tcp: "TCP 탐색", udp: "UDP 탐색", service: "서비스 식별",
};

// 실행 한 건이 이보다 오래 돌고 있으면 눈에 띄게 표시한다. 상한을 걸어 끊는 것이 아니라
// (호스트/스크립트 타임아웃은 관측을 통째로 버려서 뺐다) '오래 걸리는 중'이라는 사실만
// 보여준다 — 끊을지 기다릴지는 사람이 정한다.
const LONG_RUN_SECONDS = 600;

function stageName(stage, proto) {
  const base = STAGE_LABEL[stage] || stage || "단계";
  // 서비스 식별만 프로토콜이 갈린다. 나머지는 단계 이름에 이미 프로토콜이 들어 있어
  // 붙이면 "TCP 탐색 · TCP" 가 된다.
  return stage === "service" && proto ? `${base} · ${proto.toUpperCase()}` : base;
}

function Bar({ value, total }) {
  const pct = total > 0 ? Math.min(100, (value / total) * 100) : 0;
  return (
    <div className="trace-bar" aria-hidden="true">
      <div className="trace-bar-fill" style={{ width: `${pct}%` }} />
    </div>
  );
}

function Share({ value, total }) {
  if (!total) return null;
  return <span className="trace-share">{Math.round((value / total) * 100)}%</span>;
}

// 수확량 — 이 실행이 실제로 무엇을 담았는가. 소요만 보면 "107초 돌고 빈 XML"이 정상
// 성공과 구분되지 않는다. 그 실패를 여기서 바로 보이게 한다.
const EMPTY_HINT = "스윕이 열렸다고 확정한 포트를 봤는데 산출물이 비었습니다. "
  + "식별에 실패했거나, 그 사이 포트가 닫혔습니다.";

function Yield({ run }) {
  if (run.hosts_found == null) return null;
  return (
    <span className={`trace-yield${run.empty ? " is-empty" : ""}`}
          title={run.empty ? EMPTY_HINT : undefined}>
      호스트 {run.hosts_found} · 열림 {run.open_ports}
      {/* UDP 식별은 대개 `open|filtered` 만 남긴다. 그것을 안 그리면 endpoint 를
          실제로 담은 실행이 '열림 0 · 버전 0' 으로 보이면서 '산출물 없음' 표시도
          안 붙는다(서버는 봤으니까) - 아무것도 못 한 실행처럼 읽힌다. */}
      {run.inferred_open > 0 && <> · 추정 {run.inferred_open}</>}
      {" · 버전 "}{run.products}
      {run.empty && <b> 산출물 없음</b>}
    </span>
  );
}

function Phases({ phases }) {
  const entries = Object.entries(phases || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return null;
  return (
    <div className="trace-phases">
      {entries.map(([phase, sec]) => (
        <span key={phase} className="tag">{phase} {fmtSeconds(sec)}</span>
      ))}
    </div>
  );
}

export default function ScanTrace({ trace }) {
  const runsTotal = trace?.runs_total || 0;
  if (!runsTotal) return null;
  const total = trace.seconds_total || 0;
  const running = trace.running || [];
  const stalled = running.filter((r) => (r.elapsed_seconds || 0) >= LONG_RUN_SECONDS).length;

  return (
    <details className="trace">
      <summary>
        실행 추적
        <span className="trace-summary-meta">
          nmap {runsTotal}회 · 합계 {fmtSeconds(total)}
          {running.length ? ` · 진행 중 ${running.length}건` : ""}
          {stalled ? ` · ${fmtSeconds(LONG_RUN_SECONDS)} 초과 ${stalled}건` : ""}
        </span>
      </summary>

      {running.length > 0 && (
        <section className="trace-section">
          <h5>지금 실행 중</h5>
          <table className="trace-tbl">
            <tbody>
              {running.map((run, i) => (
                <tr key={`run-${i}`}
                    className={(run.elapsed_seconds || 0) >= LONG_RUN_SECONDS ? "is-long" : ""}>
                  <td>{stageName(run.stage, run.proto)}</td>
                  <td className="mono">{run.label || "—"}</td>
                  <td className="mono trace-ports" title={run.ports || ""}>{run.ports || "—"}</td>
                  <td className="mono trace-num">{fmtSeconds(run.elapsed_seconds)} 경과</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="trace-section">
        <h5>단계별 소요</h5>
        <table className="trace-tbl">
          <tbody>
            {(trace.by_stage || []).map((row) => (
              <tr key={`${row.stage}-${row.proto}`}>
                <td>{stageName(row.stage, row.proto)}</td>
                <td className="mono trace-num">{row.runs}회</td>
                <td className="trace-barcell"><Bar value={row.seconds} total={total} /></td>
                <td className="mono trace-num">{fmtSeconds(row.seconds)}</td>
                <td className="trace-num"><Share value={row.seconds} total={total} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {(trace.by_phase || []).length > 0 && (
        <section className="trace-section">
          <h5>nmap 내부 단계</h5>
          {/* 같은 10분이라도 포트스캔에 쓴 10분과 서비스 식별에 쓴 10분은 대책이 다르다.
              nmap 이 스스로 보고한 이름을 그대로 쓴다 — 번역해 두면 문서와 대조가 안 된다. */}
          <table className="trace-tbl">
            <tbody>
              {trace.by_phase.map((row) => (
                <tr key={row.phase}>
                  <td className="mono">{row.phase}</td>
                  <td className="trace-barcell"><Bar value={row.seconds} total={total} /></td>
                  <td className="mono trace-num">{fmtSeconds(row.seconds)}</td>
                  <td className="trace-num"><Share value={row.seconds} total={total} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {(trace.by_host || []).length > 0 && (
        <section className="trace-section">
          <h5>호스트별 소요</h5>
          <p className="trace-note">
            호스트당 프로세스를 세우는 식별 단계만 셉니다. 배치 스윕은 여러 대를 한 프로세스로
            돌아 한 대에 귀속시킬 수 없습니다.
          </p>
          <table className="trace-tbl">
            <tbody>
              {trace.by_host.map((row) => (
                <tr key={row.host}>
                  <td className="mono">{row.host}</td>
                  <td className="mono trace-num">{row.runs}회</td>
                  <td className="trace-barcell"><Bar value={row.seconds} total={total} /></td>
                  <td className="mono trace-num">{fmtSeconds(row.seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {trace.by_host_truncated && <p className="trace-note">상위 {trace.by_host.length}대만 표시합니다.</p>}
        </section>
      )}

      {(trace.slowest || []).length > 0 && (
        <section className="trace-section">
          <h5>오래 걸린 실행</h5>
          <table className="trace-tbl trace-runs">
            <tbody>
              {trace.slowest.map((run, i) => (
                <tr key={`slow-${i}`} className={run.empty ? "is-empty" : ""}>
                  <td>
                    <div>{stageName(run.stage, run.proto)}</div>
                    <div className="mono trace-sub">{run.label || "—"}</div>
                  </td>
                  <td className="mono trace-ports" title={run.ports || ""}>{run.ports || "—"}</td>
                  <td>
                    <Yield run={run} />
                    <Phases phases={run.phases} />
                  </td>
                  <td className="mono trace-num">
                    {fmtSeconds(run.seconds)}
                    {run.stopped ? <div className="trace-sub">중지됨</div>
                      : run.rc ? <div className="trace-sub">rc {run.rc}</div> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {trace.slowest_truncated && (
            <p className="trace-note">가장 오래 걸린 {trace.slowest.length}건만 표시합니다.</p>
          )}
        </section>
      )}
    </details>
  );
}

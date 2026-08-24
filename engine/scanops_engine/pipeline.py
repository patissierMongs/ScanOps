"""단계 파이프라인 — 발견 → TCP 찾기 → UDP 찾기 → 서비스 probe.

각 단계가 다음 단계 입력을 좁힌다(대역 → live → open → service). 이벤트 emit +
run-state 재개 + 중지. 재스캔(targets_ports)이면 발견·찾기를 건너뛰고 서비스 probe 만.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import nmaprun
from .spec import (DEFAULT_MAX_PARALLELISM, DEFAULT_MIN_HOSTGROUP,
                   DEFAULT_TCP_NSE_SCRIPT_TIMEOUT, DEFAULT_UDP_NSE_SCRIPT_TIMEOUT,
                                      DISCOVERY_PA, DISCOVERY_PS)
from .state import RunState
import re


# UDP 식별이 죽었을 때 한 번 갈아 끼울 nsock 엔진. nmap#3138 의 유지관리자 우회책이며
# select 는 동시 소켓 수에 제약이 있지만, UDP 식별은 이미 열린 포트 하나만 다루므로 무해하다.
_UDP_RETRY_ENGINE = "select"
# 실패한 UDP 묶음을 포트별로 쪼갤 때의 상한. 넘으면 쪼개지 않고 그 실행을 저하로 남긴다 —
# 죽은 실행이 포트를 많이 물고 있으면 쪼개는 것 자체가 프로세스 폭증이 된다.
_MAX_SPLIT_UNITS = 32


class _LockedSink:
    """식별 단계를 동시에 돌리면 이벤트가 여러 스레드에서 나온다.

    싱크는 JSONL 한 줄씩을 쓰는데, 잠그지 않으면 줄이 서로 섞여 읽는 쪽이 파싱에 실패한다.
    직렬로 돌 때는 락이 사실상 비용이 없으므로 항상 감싼다.
    """

    def __init__(self, inner, lock):
        self._inner, self._lock = inner, lock

    def emit(self, *args, **kwargs):
        with self._lock:
            self._inner.emit(*args, **kwargs)


def _batches(items, size):
    size = max(1, size)
    return [items[i:i + size] for i in range(0, len(items), size)]


class Pipeline:
    def __init__(self, spec, sink, nmap):
        self.spec = spec
        self._lock = threading.Lock()
        self.sink = _LockedSink(sink, self._lock)
        self.nmap = nmap
        self.out = Path(spec.out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.state = RunState(self.out / "run-state.json")
        self.counts = {"live": 0, "open_tcp": 0, "open_udp": 0, "services": 0, "errors": 0}
        self.open_map = self.state.get("open_map") or {}

    # ── 공통 ──
    def _execution_meta(self, stage, args, base, targets=None) -> dict:
        """Explain why this Nmap process is grouped or isolated."""
        name = Path(base).name
        proto = "udp" if "-sU" in args or stage == "udp" else "tcp"
        if stage == "discovery":
            ui_stage = "discovery"
            role = "authority"
            reason = "대상 전체의 응답 호스트를 Nmap 자체 병렬화로 함께 확인합니다."
        elif stage in {"tcp", "udp"}:
            ui_stage = stage
            role = "authority"
            reason = "같은 배치의 포트 상태를 한 번에 확인해 프로세스 중복을 줄입니다."
        else:
            ui_stage = f"{proto}_service"
            role = ("authority" if (self.spec.rescan_units or self.spec.targets_ports)
                    else "enrichment")
            reason = (
                "방화벽 없는 내부망에서 배치에 등장한 TCP 포트 합집합을 한 번에 실행해 "
                "Nmap 자체 호스트 병렬화를 사용합니다."
                if proto == "tcp" else
                "UDP 응답 대기 교차곱을 피하려고 실제로 해당 포트를 연 호스트끼리만 묶습니다."
            )
        individual = stage == "service" and not name.startswith(f"stage3-{proto}-b")
        if individual:
            reason = "공통 실행의 실패를 격리하거나 지정된 재스캔 범위만 정확히 확인합니다."
        if "--nsock-engine" in args:
            reason = "UDP 서비스 프로브 오류 뒤 nsock 엔진을 변경해 같은 범위를 복구합니다."
        # 지연 진단이 읽는 값들. 대상과 포트를 실을 자리가 없으면 화면의 '호스트별 소요'
        # 와 진행 중 표가 영원히 빈 채로 남는다 - 어느 호스트가 끌고 있는지가 이 도구를
        # 쓰는 이유 중 하나다.
        #
        # **타깃은 호출부가 알려 준 것만 쓴다.** argv 에서 '옵션이 아닌 값' 을 골라내려 하면
        # 재시도 수·묶음 크기·포트 스펙·스크립트 상한이 전부 걸린다(실측: 2·64·100·2m 이
        # 호스트로 잡혔다). 그러면 한 대짜리 실행이 '6대' 로 적히고, 호스트별 집계는 항목이
        # 하나일 때만 세므로 그 표가 통째로 빈다.
        hosts = [h for h in (targets or []) if isinstance(h, str)]
        try:
            ports = args[args.index("-p") + 1]
        except (ValueError, IndexError):
            ports = ""
        return {
            "stage": ui_stage,
            "group": "individual" if individual else "common",
            "role": role,
            "reason": reason,
            "artifact": name,
            "proto": proto,
            "hosts": hosts,
            "label": hosts[0] if len(hosts) == 1 else f"{len(hosts)}대",
            "ports": ports,
        }

    def _nmap(self, stage, args, base, fatal=True, targets=None) -> dict:
        """``fatal=False`` 면 rc!=0 을 기록만 하고 counts["errors"] 를 올리지 않는다.

        run() 은 errors 로 job status 를 정하므로, 격리된 enrichment 실패까지 여기서 세면
        실패를 격리한 의미가 없어진다 — 실행 전체가 그대로 failed 가 된다.
        """
        meta = self._execution_meta(stage, args, base, targets)
        execution_id = f"{meta['artifact']}:{time.time_ns()}"
        argv = nmaprun.build_command(self.nmap, args, base, sudo_mode=self.spec.sudo)
        self.sink.emit("command_start", execution_id=execution_id, argv=argv, **meta)
        # 연 것은 반드시 닫는다. run() 이 던지면(프로세스 생성 실패, 로그 파일 열기 실패,
        # KeyboardInterrupt 등) 이 아래의 command_done 도 상위의 job_done 도 기록되지
        # 않는다. 읽는 쪽은 job_done 이 있을 때만 열린 실행을 닫으므로, 그 실행은 UI 에서
        # 영원히 '실행 중' 으로 남고 경과시간이 폴링할 때마다 늘어난다 - 워커가 이미
        # 실패로 마감한 스캔에서도 그렇다.
        started = time.time()
        try:
            r = nmaprun.run(
                self.nmap, args, base, sudo_mode=self.spec.sudo,
                progress=lambda p: self.sink.emit("stage_progress", stage=stage, percent=p),
                stop_requested=self.state.stopped,
                watchdog_seconds=self.spec.watchdog_seconds)
        except BaseException as exc:
            self.sink.emit(
                "command_done", execution_id=execution_id,
                seconds=round(time.time() - started, 2), rc=None, outcome="error",
                timed_out=[], timeout_count=0, watchdog_seconds=0,
                retransmission_cap_hosts=[], retransmission_cap_count=0,
                error=type(exc).__name__, **meta)
            raise
        r["execution_id"] = execution_id
        timed_out = nmaprun.timed_out(Path(str(base) + ".xml")) if r["rc"] == 0 else []
        cap_hosts = [host for host in (r.get("retransmission_cap_hosts") or [])
                     if isinstance(host, str)]
        if cap_hosts:
            retry_stage = {
                "tcp_service": "service:tcp", "udp_service": "service:udp",
            }.get(meta["stage"], meta["stage"])
            with self._lock:
                self.state.add_retransmission_cap(retry_stage, cap_hosts)
                self.state.save()
            try:
                retry_limit = int(args[args.index("--max-retries") + 1])
            except (ValueError, IndexError):
                retry_limit = None
            self.sink.emit(
                "retransmission_cap_hit", stage=meta["stage"], hosts=cap_hosts,
                count=len(cap_hosts), max_retries=retry_limit,
            )
        # 워치독이 끊은 실행은 '오류'가 아니라 '상한 초과'로 부른다. rc 만 보면 nmap 이 죽은
        # 것과 우리가 끊은 것이 같아 보이는데, 사용자가 할 일이 다르다(전자는 원인 조사,
        # 후자는 상한을 늘릴지 대상을 줄일지 결정).
        outcome = ("stopped" if r.get("stopped")
                   else "watchdog" if r.get("timed_out_by_watchdog")
                   else "error" if r["rc"] != 0
                   else "timeout" if timed_out else "done")
        # 지연 진단의 두 재료. **총 소요만으로는 답이 안 나온다** - 같은 10분이라도 어느
        # nmap 내부 단계에 썼는지(phases), 그리고 그러고도 무엇을 담았는지(yield)를 알아야
        # 다음 스캔에서 무엇을 바꿀지 정할 수 있다. 107초 돌고 빈 산출물을 남긴 실행이
        # '완료' 와 구분되지 않던 것이 이 값이 없을 때의 모습이다.
        self.sink.emit(
            "command_done", execution_id=execution_id, seconds=r["seconds"], rc=r["rc"],
            outcome=outcome, timed_out=timed_out, timeout_count=len(timed_out),
            watchdog_seconds=(self.spec.watchdog_seconds
                              if r.get("timed_out_by_watchdog") else 0),
            retransmission_cap_hosts=cap_hosts,
            retransmission_cap_count=len(cap_hosts),
            phases=r.get("phases") or {},
            # 빈손이 곧 실패인 것은 서비스 probe 뿐이다 - 발견과 스윕은 정상적으로
            # 아무것도 못 찾을 수 있다.
            **nmaprun.artifact_yield(Path(str(base) + ".xml"),
                                     expects_services=meta["stage"].endswith("service")),
            **meta,
        )
        if r.get("stopped"):
            self.sink.emit(
                "stage_done", stage=stage, seconds=r["seconds"], counts={"stopped": True},
            )
        elif r["rc"] != 0:
            if fatal:
                with self._lock:
                    self.counts["errors"] += 1
            self.sink.emit("error", stage=stage, execution_id=execution_id,
                           proto="udp" if "-sU" in args else "tcp",
                           rc=r["rc"], fatal=fatal,
                           cmd=" ".join(map(str, r["cmd"])))
        return r

    def _record_coverage(self, artifact, proto, role, hosts, ports, finished) -> None:
        """이 nmap 실행이 **무엇을 · 어디까지 · 어떤 자격으로** 훑었는지 기록한다.

        지금까지 백엔드는 이 사실을 산출물 glob 과 배치 슬라이스(``live[i*b:(i+1)*b]``)로
        되짚었다. 되짚기는 규칙이 바뀌는 순간 조용히 틀리고, ``--open`` 때문에 열린 포트가
        없는 호스트는 XML 에 아예 안 나타나서 '훑었는가'를 파일에서 읽을 수도 없다.
        그래서 **만든 쪽이 적어 둔다** - 이 저장소가 이미 쓰는 규칙이다
        (scan_summary 의 범위 꼬리표: "만든 쪽이 적어 준 값이 파싱보다 먼저").

        ``role`` 이 핵심이다. 같은 stage3 XML 이라도 전체 스캔에서는 enrichment 이고
        포트 재스캔에서는 그 자체가 authority 다. 역할을 안 적으면 읽는 쪽이 파일 이름으로
        추측하게 되고, 그러면 완결된 TCP sweep 의 권한을 enrichment 타임아웃 하나가 빼앗는다.
        """
        entry = {"artifact": artifact, "proto": proto, "role": role,
                 "hosts": list(hosts), "ports": ports, "finished": bool(finished)}
        # 식별 단계는 동시에 돌 수 있고 이건 read-modify-write 라, 잠그지 않으면 기록이
        # 통째로 사라진다 - 그러면 그 산출물이 커버한 호스트가 '훑지 않음'이 되어
        # (fail-closed 방향이긴 하지만) 닫아야 할 것을 못 닫는다.
        with self._lock:
            log = list(self.state.get("coverage") or [])
            log.append(entry)
            self.state.set("coverage", log)
            self.state.save()

    def _save(self):
        self.state.set("open_map", self.open_map)
        self.state.save()

    def _exclude_args(self) -> list:
        # Nmap 7.99는 반복 --exclude 를 누적하지 않고 마지막 값만 적용한다.
        # 검증된 토큰을 단일 comma-list로 전달해야 모든 제외가 보장된다.
        args = ["--exclude", ",".join(self.spec.exclude)] if self.spec.exclude else []
        # 포트 제외는 **모든 단계**에 실어야 한다. 한 단계라도 빠지면 그 단계가 그 포트를
        # 건드리고, 안전 컨트롤로서는 의미가 없어진다. 발견 단계는 -sn 이라 포트를 안 보지만
        # 그래도 같이 싣는다(실측: nmap 이 거부하지 않는다) - 나중에 발견 방식이 바뀌어도
        # 제외가 조용히 새지 않게 하려는 것이다.
        if self.spec.exclude_ports.strip():
            args += ["--exclude-ports", self.spec.exclude_ports.strip()]
        return args

    def _throughput_args(self, syn: bool, groups_hosts: bool = True) -> list:
        """모든 단계가 함께 지는 처리량 정책 — 한 곳에서만 정한다.

        **이 셋은 가속 옵션이 아니다.** 셋 다 상한이거나 조건부 우회이고, 여기 있는 이유는
        스캔 서버와 대상 장비의 부하를 예측 가능하게 묶어 두기 위해서다.

        * ``--max-parallelism`` 은 동시 프로브의 **상한**이다(하한이 아니다). 그래서 이 값을
          준다고 빨라지지 않는다 - 오히려 nmap 의 적응형 병렬성이 이보다 높이 올라갈 수
          있는 빠른 LAN 에서는 스스로를 100 으로 묶는다. 그것이 의도다(부하 예측 가능성).
        * ``--min-hostgroup`` 은 포트/버전 스캔의 묶음 크기 **하한**이다. nmap 문서는 이
          옵션이 호스트 발견 단계(``-sn`` 포함)에는 **효과가 없다**고 명시하므로, 그 단계에는
          싣지 않는다(``groups_hosts=False``) - 없는 효과를 명령줄에 적어 두면 읽는 사람이
          그 단계도 묶여 도는 줄 안다.
        * ``--defeat-rst-ratelimit`` 은 **SYN 스캔 전용**이다(``-sT``·``-sU``·``-sn`` 과 함께
          주면 nmap 이 fatal 로 끝난다). 대상이 스스로 거는 RST 율제한 보호를 무시하므로
          부하를 **올리는** 쪽이다 - 노후 장비 대역에는 gentle 강도를 쓴다.
        """
        args = ["--max-parallelism", str(DEFAULT_MAX_PARALLELISM)]
        if groups_hosts:
            args = ["--min-hostgroup", str(DEFAULT_MIN_HOSTGROUP)] + args
        if syn:
            args.append("--defeat-rst-ratelimit")
        return args

    def _tcp_scan_flag(self) -> str:
        return {"syn": "-sS", "connect": "-sT"}[self.spec.tcp.scan_type]

    def _stage_plan(self) -> list[str]:
        """UI가 시작 전부터 그릴 수 있는 실제 실행 단계를 순서대로 돌려준다."""
        if self.spec.rescan_units or self.spec.targets_ports:
            return ["service"] if self.spec.service.enabled else []
        plan = ["discovery"]
        tcp_needed = self.spec.tcp.enabled or any((m or {}).get("tcp") for m in self.open_map.values())
        udp_needed = self.spec.udp.enabled or any((m or {}).get("udp") for m in self.open_map.values())
        if self.spec.tcp.enabled:
            plan.append("tcp")
        if tcp_needed and self.spec.service.enabled:
            plan.append("tcp_service")
        if self.spec.udp.enabled:
            plan.append("udp")
        if udp_needed and self.spec.service.enabled:
            plan.append("udp_service")
        return plan

    def _skip_remaining_stages(self) -> None:
        """생존 호스트가 0이라 돌지 않은 계획 단계를 끝난 것으로 닫는다."""
        for stage in self._stage_plan():
            if stage == "discovery":
                continue
            self.sink.emit("stage_done", stage=stage, seconds=0.0,
                           counts={"skipped": True, "live": 0})

    # ── 진입 ──
    def run(self) -> dict:
        t0 = time.time()
        self.sink.emit("job_start", job_id=self.spec.job_id, targets=self.spec.targets,
                       rescan=bool(self.spec.targets_ports or self.spec.rescan_units))
        self.sink.emit("stage_plan", stages=self._stage_plan())
        if self.spec.rescan_units:
            # 발견(IP:포트)별 개별 재스캔 — 항목마다 nmap 1개(그 ip·그 포트만).
            if self.spec.service.enabled and not self.state.stopped():
                self._rescan_units()
        else:
            if self.spec.targets_ports:
                # 타겟 포트 재스캔 — 여기서는 stage3 가 유일한 폐쇄 근거라 호스트 단위로 간다.
                for ip, ports in self.spec.targets_ports.items():
                    self.open_map.setdefault(ip, {})["tcp"] = sorted({int(p) for p in ports})
                self._save()
                if (self.counts["errors"] == 0 and self.spec.service.enabled
                        and not self.state.stopped()):
                    self._service()
            else:
                live = self._discovery()
                if live and not self.state.stopped() and self.counts["errors"] == 0:
                    # 전체 스캔은 배치마다 sweep → 식별까지 끝내고 다음 배치로 간다.
                    self._scan_batches(live)
                elif not live and not self.state.stopped() and self.counts["errors"] == 0:
                    # 응답한 호스트가 없으면 뒤 단계는 **돌 것이 없다.** 계획에만 남겨 두면
                    # 잡은 done 으로 끝나는데 그 단계들은 영원히 '대기' 로 남아, 전체 100%
                    # 옆에 시작도 안 한 칩이 붙는다. 끝났다는 사실을 남기되 counts 로
                    # '생략' 임을 밝힌다 - 돈 것과 돌 것이 없던 것은 다른 사실이다.
                    self._skip_remaining_stages()
        secs = round(time.time() - t0, 2)
        status = ("stopped" if self.state.stopped()
                  else "failed" if self.counts["errors"] else "done")
        self.sink.emit("job_done", status=status, seconds=secs, counts=self.counts)
        if status == "done":
            self.state.mark_done("job")
            self.state.save()
        return self.counts

    # ── Stage 0 ──
    def _discovery(self) -> list:
        sp = self.spec.discovery
        if not sp.enabled or sp.mode == "pn":
            live = list(self.spec.targets)   # -Pn: 타겟을 그대로 넘겨 찾기 단계가 직접 스캔
            self.counts["live"] = len(live)
            self.sink.emit("stage_done", stage="discovery", seconds=0.0,
                           counts={"mode": "pn", "live": len(live)})
            self.state.set("live", live)
            self.state.save()
            return live
        if self.state.done("discovery") and self.state.get("live") is not None:
            live = self.state.get("live")
            self.counts["live"] = len(live)
            self.sink.emit("stage_done", stage="discovery", seconds=0.0,
                           counts={"live": len(live), "cached": True})
            return live
        self.sink.emit("stage_start", stage="discovery", targets=self.spec.targets)
        self.sink.emit(
            "stage_activity", stage="discovery", percent=0,
            current_hosts=list(self.spec.targets[:8]),
            current_host_count=len(self.spec.targets),
        )
        args = ["-sn", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", sp.timing,
                "--reason", "--max-retries", str(sp.max_retries)]
        # 발견은 -sn 이라 두 가지가 함께 빠진다 - SYN 스캔이 아니므로
        # --defeat-rst-ratelimit 를 얹으면 nmap 이 fatal 로 끝나고, nmap 문서상
        # --min-hostgroup 은 호스트 발견 단계에 아무 효과가 없다.
        args += self._throughput_args(syn=False, groups_hosts=False)
        args += self._exclude_args()
        args += list(self.spec.targets)
        base = self.out / "stage0-discovery"
        r = self._nmap("discovery", args, base, targets=list(self.spec.targets))
        if r.get("stopped") or r["rc"] != 0:
            return []
        self._record_coverage("stage0-discovery.xml", "", "discovery",
                              self.spec.targets, "", True)
        gave_up = nmaprun.timed_out(Path(str(base) + ".xml"))
        with self._lock:
            self.state.update_gave_up("discovery", gave_up, [])
        if gave_up:
            self.sink.emit("hosts_gave_up", stage="discovery", hosts=gave_up,
                           count=len(gave_up))
        live = nmaprun.hosts_up(Path(str(base) + ".xml"))
        self.counts["live"] = len(live)
        self.sink.emit("hosts_up", stage="discovery", hosts=live, count=len(live))
        self.sink.emit("stage_done", stage="discovery", seconds=r["seconds"], counts={"live": len(live)})
        self.state.set("live", live)
        self.state.mark_done("discovery")
        self.state.save()
        return live

    # ── Stage 1/2/3: 배치마다 sweep → 식별까지 끝내고 다음 배치로 ──
    def _scan_batches(self, live) -> bool:
        """한 배치를 **끝까지** 처리하고 다음 배치로 간다.

        예전에는 TCP sweep 을 전 배치에 대해 끝내고, UDP sweep 을 전 배치에 대해 끝내고,
        그 다음에야 식별을 호스트 하나씩 돌았다. 그래서 식별이 시작될 때까지 아무 서비스
        정보도 나오지 않았고, 중간에 멈추면 그때까지의 결과가 포트 목록에서 끝났다.
        배치 단위로 닫으면 배치 하나가 끝날 때마다 완성된 결과가 나오고, 중지·이어가기도
        같은 경계를 쓴다.

        식별은 그 배치에서 **실제로 열린 포트만** 본다. 전체 포트 범위를 다시 훑지 않는다.
        """
        sp = self.spec.service
        batches = _batches(live, self.spec.batch_size)
        total_batches = len(batches)
        sweeps = [p for p in ("tcp", "udp")
                  if (self.spec.tcp if p == "tcp" else self.spec.udp).enabled]
        # sweep 을 끈 채 이어가는 실행(이미 open_map 이 있는 경우)도 식별은 돌아야 한다.
        # sweep 목록만 보면 그 실행이 통째로 아무 일도 하지 않는다.
        protos = [p for p in ("tcp", "udp")
                  if p in sweeps or any((m or {}).get(p) for m in self.open_map.values())]
        started = set()

        def start(stage, **fields):
            if stage not in started:
                self.sink.emit("stage_start", stage=stage, **fields)
                started.add(stage)

        secs = {"tcp": 0.0, "udp": 0.0, "tcp_service": 0.0, "udp_service": 0.0}
        nsvc = {"tcp": 0, "udp": 0}

        def finish(stopped=False):
            for proto in sweeps:
                # **이어가기가 건너뛴 배치까지 센다.** 예전에는 이 프로세스에서 실제로 훑은
                # 배치만 더하는 누산기를 썼는데, 중지 후 이어가면 이미 끝낸 배치는
                # `batch_done()` 으로 건너뛰므로 그 포트가 빠졌다. 서비스 단계만 남기고
                # 이어가면 총계가 0 으로 마감돼, 타임라인과 영속 단계 요약이 그 실행이
                # 실제로 인입한 발견·`open_map` 과 어긋났다.
                #
                # `open_map` 은 상태에 영속되어 이어가기 너머로 남는 **누적 기록**이고,
                # 바로 아래 호스트 수도 이미 그것을 센다. 같은 근거에서 두 수를 뽑아
                # 서로 어긋날 수 없게 한다.
                hosts_open = [m for m in self.open_map.values() if m.get(proto)]
                nhosts = len(hosts_open)
                total_open = sum(len(m.get(proto) or []) for m in hosts_open)
                self.counts["open_tcp" if proto == "tcp" else "open_udp"] = total_open
                self.sink.emit(
                    "stage_done", stage=proto, seconds=round(secs[proto], 2),
                    counts={"stopped": True} if stopped
                    else {"open_ports": total_open, "hosts": nhosts})
            if sp.enabled:
                for proto in protos:
                    service_stage = f"{proto}_service"
                    self.sink.emit(
                        "stage_done", stage=service_stage,
                        seconds=round(secs[service_stage], 2),
                        counts={"stopped": True} if stopped
                        else {"services": nsvc[proto]})
                self.counts["services"] = sum(nsvc.values())

        for bi, batch in enumerate(batches):
            if self.state.stopped():
                finish(stopped=True)
                return False
            batch_probed, batch_failed = set(), set()
            for proto in protos:
                if proto in sweeps and not self.state.batch_done(f"{proto}:{bi}"):
                    stage_spec = self.spec.tcp if proto == "tcp" else self.spec.udp
                    start(proto, hosts=len(live), ports=stage_spec.ports)
                    self.sink.emit(
                        "stage_activity", stage=proto,
                        percent=round(bi / total_batches * 100, 1),
                        batch=bi + 1, batch_total=total_batches,
                        current_hosts=list(batch[:8]), current_host_count=len(batch),
                    )
                    elapsed, found = self._sweep_batch(proto, bi, batch)
                    secs[proto] += elapsed
                    if found is None:
                        finish(stopped=self.state.stopped())
                        return False
                    self.sink.emit(
                        "stage_activity", stage=proto,
                        percent=round((bi + 1) / total_batches * 100, 1),
                        batch=bi + 1, batch_total=total_batches,
                        current_hosts=[], current_host_count=0,
                    )
                    self.state.mark_batch_done(f"{proto}:{bi}")
                    self._save()
                if not sp.enabled or self.state.batch_done(f"svc-{proto}:{bi}"):
                    continue
                service_stage = f"{proto}_service"
                start(service_stage, hosts=len(live))
                elapsed, rows, probed, failed = self._service_batch(
                    proto, bi, batch, sp, total_batches,
                )
                secs[service_stage] += elapsed
                nsvc[proto] += len(rows)
                batch_probed |= probed
                batch_failed |= failed
                if self.state.stopped():
                    finish(stopped=True)
                    return False
                self.state.mark_batch_done(f"svc-{proto}:{bi}")
                self._save()
            # 이 배치의 **모든** 프로토콜을 끝낸 뒤에 찍는다. 프로토콜 하나가 끝날 때마다
            # 찍으면 TCP 만 끝낸 호스트가 UDP 식별 실패와 무관하게 완료로 남는다.
            for ip in sorted(batch_probed - batch_failed, key=nmaprun._ipkey):
                self.state.mark_service_done(ip)
            if batch_probed:
                self._save()
        for proto in sweeps:
            self.state.mark_done(proto)
        finish()
        self._save()
        return True

    def _sweep_batch(self, proto, bi, batch):
        """배치 하나의 포트 스윕. 반환: (초, {ip: [열린 포트]}) — 실패/중지면 두 번째가 None."""
        sp = self.spec.tcp if proto == "tcp" else self.spec.udp
        args = [("-sU" if proto == "udp" else self._tcp_scan_flag()),
                "-Pn", "-n", "--open",
                sp.timing, "--reason", "--max-retries", str(sp.max_retries)]
        args += self._throughput_args(syn=proto == "tcp" and self.spec.tcp.scan_type == "syn")
        if proto == "tcp" and sp.min_rate > 0:
            args += ["--min-rate", str(sp.min_rate)]
        args += ["-p", sp.ports]
        args += self._exclude_args()
        args += batch
        base = self.out / f"stage-{proto}-b{bi}"
        r = self._nmap(proto, args, base, targets=list(batch))
        ok = not r.get("stopped") and r["rc"] == 0
        # 되짚기가 아니라 명령줄에 실제로 올린 batch 를 그대로 적는다.
        self._record_coverage(f"stage-{proto}-b{bi}.xml", proto, "authority",
                              batch, sp.ports, ok)
        if not ok:
            return r["seconds"], None
        xml = Path(str(base) + ".xml")
        # 상한을 넘겨 포기당한 호스트는 따로 모은다 - 이 실행에서는 부재를 말할 자격이 없고,
        # 나중에 그 호스트들만 다시 스캔할 대상 목록이 된다.
        gave_up = nmaprun.timed_out(xml)
        with self._lock:
            self.state.update_gave_up(
                proto, gave_up, [h for h in batch if h not in set(gave_up)])
        if gave_up:
            self.sink.emit("hosts_gave_up", stage=proto, hosts=gave_up, count=len(gave_up))
        found = nmaprun.open_ports(xml, proto=proto)
        for ip, ports in found.items():
            self.open_map.setdefault(ip, {})[proto] = ports
            self.sink.emit("ports_open", stage=proto, ip=ip, ports=ports)
        self._save()
        return r["seconds"], found

    def _service_batch(self, proto, bi, batch, sp, total_batches):
        """그 배치에서 발견한 포트만 서비스 식별한다.

        방화벽/ACL silent drop 이 없는 서버팜을 전제로 TCP 는 배치의 등장 포트 합집합을 모든
        대상에 한 번 실행한다. 닫힌 포트는 RST 로 즉시 끝나고 -sV/NSE 는 열린 포트에만 붙으므로
        여러 프로세스를 세우는 것보다 Nmap 자체 호스트 병렬화가 빠르다. UDP 는 방화벽이 없어도
        ICMP unreachable 율제한이 있어 교차곱이 비싸므로 실제 host×port 조합만 묶는다.
        공통 실행 자체가 실패한 경우에만 호스트별 실제 열린 포트로 격리한다.
        """
        targets = {}
        for ip in batch:
            ports = (self.open_map.get(ip) or {}).get(proto) or []
            if ports:
                targets[ip] = {proto: ports}
        if not targets:
            self.sink.emit(
                "stage_activity", stage=f"{proto}_service",
                percent=round((bi + 1) / total_batches * 100, 1),
                batch=bi + 1, batch_total=total_batches,
                current_hosts=[], current_host_count=0,
                completed_hosts=0, total_hosts=0,
            )
            return 0.0, [], set(), set()
        pending = sorted(targets, key=nmaprun._ipkey)
        service_stage = f"{proto}_service"
        if sp.confirm:
            return self._probe_hosts(
                pending, targets, sp, isolate=True, mark_done=False,
                activity={"stage": service_stage, "batch": bi + 1,
                          "batch_total": total_batches},
            )
        if proto == "tcp":
            union_ports = sorted({port for ip in pending for port in targets[ip][proto]})
            units = [(tuple(pending), union_ports)]
        else:
            by_hosts = {}
            for port in sorted({port for ip in pending for port in targets[ip][proto]}):
                hosts = tuple(ip for ip in pending if port in targets[ip][proto])
                by_hosts.setdefault(hosts, []).append(port)
            units = [(hosts, ports) for hosts, ports in by_hosts.items()]
            # 공유 호스트 집합이 하나도 없으면 포트 중심으로 다시 나눌 이득이 없다. 기존
            # 호스트별 묶음이 이미 정확하고 실패 시 UDP 포트 분할 복구도 그대로 제공한다.
            if not any(len(hosts) > 1 for hosts, _ports in units):
                return self._probe_hosts(
                    pending, targets, sp, isolate=True, mark_done=False,
                    activity={"stage": service_stage, "batch": bi + 1,
                              "batch_total": total_batches},
                )

        total_pairs = sum(len(hosts) * len(ports) for hosts, ports in units)
        completed_pairs = 0
        elapsed, rows, probed, failed = 0.0, [], set(), set()
        failed_units = []
        remaining = {host: sum(1 for hosts, _ports in units if host in hosts)
                     for host in pending}
        workers = min(max(1, int(sp.workers)), len(units))
        indexed = list(enumerate(units))
        for wave in _batches(indexed, workers):
            if self.state.stopped():
                return elapsed, rows, probed, failed
            active_hosts = sorted({host for _gi, (hosts, _ports) in wave for host in hosts},
                                  key=nmaprun._ipkey)
            self.sink.emit(
                "stage_activity", stage=service_stage,
                percent=round((bi + completed_pairs / total_pairs) / total_batches * 100, 1),
                batch=bi + 1, batch_total=total_batches,
                current_hosts=list(active_hosts[:8]), current_host_count=len(active_hosts),
                completed_hosts=sum(count == 0 for count in remaining.values()),
                total_hosts=len(pending),
            )
            wave_started = time.time()
            if len(wave) == 1:
                gi, (hosts, ports) = wave[0]
                results = [(gi, hosts, ports, *self._probe_batch_protocol(
                    hosts, proto, ports, sp, bi, gi, isolate=True,
                ))]
            else:
                with ThreadPoolExecutor(max_workers=len(wave)) as pool:
                    futures = [
                        (gi, hosts, ports, pool.submit(
                            self._probe_batch_protocol, hosts, proto, ports, sp, bi, gi, True,
                        ))
                        for gi, (hosts, ports) in wave
                    ]
                    results = [(gi, hosts, ports, *future.result())
                               for gi, hosts, ports, future in futures]
            # 이 파도는 **동시에** 돈다. 각 명령의 소요를 더하면 10분짜리 16개가 도는
            # 파도가 160분으로 남는다 - 그 값이 곧 서비스 단계의 seconds 로 나가므로,
            # 지연을 보려고 읽는 숫자가 가장 크게 틀린다. 벽시계로 잰다(그룹 안에서
            # 순차로 도는 재시도는 벽시계에 자연히 포함되고, 파도 밖의 순차 폴백은
            # 아래에서 각자 더한다).
            elapsed += round(max(time.time() - wave_started, 0.0), 2)
            for _gi, hosts, ports, _seconds, found, ok in results:
                rows += found
                if ok:
                    probed.update(hosts)
                    completed_pairs += len(hosts) * len(ports)
                    for host in hosts:
                        remaining[host] -= 1
                else:
                    failed_units.append((hosts, ports))
            self.sink.emit(
                "stage_activity", stage=service_stage,
                percent=round((bi + completed_pairs / total_pairs) / total_batches * 100, 1),
                batch=bi + 1, batch_total=total_batches,
                current_hosts=[], current_host_count=0,
                completed_hosts=sum(count == 0 for count in remaining.values()),
                total_hosts=len(pending),
            )

        if failed_units:
            fallback_targets = {}
            for hosts, ports in failed_units:
                for host in hosts:
                    current = fallback_targets.setdefault(host, {proto: []})[proto]
                    actual = set(targets.get(host, {}).get(proto) or [])
                    current.extend(port for port in ports if port in actual and port not in current)
            failed_pairs = sum(len(m[proto]) for m in fallback_targets.values())
            fallback = self._probe_hosts(
                sorted(fallback_targets, key=nmaprun._ipkey), fallback_targets, sp,
                isolate=True, mark_done=False,
                activity={"stage": service_stage, "batch": bi + 1,
                          "batch_total": total_batches,
                          "phase_start": completed_pairs / total_pairs,
                          "phase_span": failed_pairs / total_pairs},
            )
            elapsed += fallback[0]
            rows += fallback[1]
            probed |= fallback[2]
            failed |= fallback[3]
        self.sink.emit(
            "stage_activity", stage=service_stage,
            percent=round((bi + 1) / total_batches * 100, 1),
            batch=bi + 1, batch_total=total_batches,
            current_hosts=[], current_host_count=0,
            completed_hosts=len(set(pending) - failed), total_hosts=len(pending),
        )
        return elapsed, rows, probed, failed

    # ── Stage 3: 서비스 probe (그 배치에서 실제로 열린 포트에만) ──
    def _probe_args(self, proto, pspec, sp, retries=None) -> list:
        """식별 nmap 인자 — 호스트 하나든 배치든 **같은 명령**이어야 한다.

        여기가 갈리면 재스캔에서 본 서비스와 전체 스캔에서 본 서비스가 달라진다.
        """
        if proto == "tcp":
            # standalone 과 같이 TCP identify 에서는 역방향 DNS를 허용한다.
            args = [self._tcp_scan_flag(), "-Pn", "-sV"]
        else:
            args = ["-sU", "-Pn", "-n", "-sV"]
        # --version-all(강도 9)은 TCP 에만 — 수다스러운/증폭형 UDP 서비스에서
        # 거대·비정상 응답으로 nmap 이 fatal 종료될 위험이 크고 식별 이득은 미미하다.
        if sp.version_all and proto == "tcp":
            args.append("--version-all")
        elif sp.version_light:
            args.append("--version-light")
        if retries is None:
            retries = sp.max_retries if proto == "tcp" else sp.udp_max_retries
        args += ["--open", "--reason", sp.timing, "--max-retries", str(retries), "-p", pspec]
        # 식별에도 같은 처리량 정책을 싣는다 — 예전에는 스윕에만 있어서 식별이 꼬리였다.
        args += self._throughput_args(
            syn=proto == "tcp" and self.spec.tcp.scan_type == "syn")
        # 웹에서 선택한 스크립트는 build_job_spec 이 TCP 와 UDP/both 로 나눠 준다. UDP 도 sweep 이
        # 실제로 연 포트만 대상으로 실행하며, 스크립트 상한으로 느린 NSE 꼬리를 제한한다.
        # 이 상한은 초과한 스크립트 인스턴스만 죽이고 포트 표는 남긴다(--host-timeout 과 다름).
        scripts = sp.nse if proto == "tcp" else sp.udp_nse
        if scripts:
            script_timeout = (DEFAULT_TCP_NSE_SCRIPT_TIMEOUT if proto == "tcp"
                              else DEFAULT_UDP_NSE_SCRIPT_TIMEOUT)
            args += ["--script", ",".join(scripts),
                     "--script-timeout", script_timeout]
        args += self._exclude_args()
        return args

    def _probe_batch_protocol(self, targets, proto, ports, sp, bi, group, isolate=False):
        """한 배치의 열린 포트 합집합을 Nmap 한 프로세스로 서비스 식별한다."""
        pspec = ("T:" if proto == "tcp" else "U:") + ",".join(map(str, ports))
        args = self._probe_args(proto, pspec, sp)
        args += list(targets)
        base = self.out / f"stage3-{proto}-b{bi}-g{group}"
        r = self._nmap("service", args, base, fatal=not isolate, targets=list(targets))
        ok = not r.get("stopped") and r["rc"] == 0
        first_seconds = 0.0   # 재시도가 있었을 때만 채워진다(아래).
        if not ok and not r.get("stopped") and proto == "udp" and not self.state.stopped():
            retry_started = time.time()
            failed_execution_id = r.get("execution_id")
            # 실패한 첫 시도의 시간도 이 단계가 쓴 시간이다. 아래에서 r 이 재시도 결과로
            # 덮여 쓰이므로 여기서 붙잡아 둔다 - 안 그러면 대부분을 첫 시도에서 쓴 실행이
            # 짧은 재시도 시간만으로 끝난 것처럼 남는다(_service_batch 가 이 값으로 단계
            # 소요를 만든다). 지연을 추적하려고 보는 값이 정확히 그 지연을 감춘다.
            first_seconds = r.get("seconds") or 0
            # **임시 base 로 돌린다.** 같은 -oA 를 쓰면 nmap 이 시작하자마자 첫 실행의
            # 산출물을 잘라 버린다. 워치독이 끊은 뒤 복구해 둔 관측이 바로 그때 사라지고,
            # 재시도까지 실패하면 첫 실행이 남긴 부분 관측만 더 나쁜 것으로 바뀐다 -
            # terminal 인입은 부분 stage3 산출물도 읽으므로 그 손실이 그대로 결과가 된다.
            alt_base = nmaprun.retry_base(base)
            r = self._nmap("service", ["--nsock-engine", _UDP_RETRY_ENGINE] + args,
                           alt_base, fatal=not isolate, targets=list(targets))
            ok = not r.get("stopped") and r["rc"] == 0 and nmaprun.xml_usable(alt_base)
            if ok:
                nmaprun.adopt_artifacts(alt_base, base)
            else:
                nmaprun.discard_artifacts(alt_base)
            self.sink.emit(
                "service_retry", stage="service", proto=proto,
                hosts=list(targets), ports=list(ports), port_spec=pspec,
                engine=_UDP_RETRY_ENGINE, reason="udp_nsock_engine_fallback",
                outcome="recovered" if ok else "stopped" if r.get("stopped") else "failed",
                recovered=ok, seconds=round(max(time.time() - retry_started, 0), 2),
                rc=r.get("rc"), recovery_of_execution_id=failed_execution_id,
                execution_id=r.get("execution_id"),
            )
        if ok:
            gave_up = nmaprun.timed_out(Path(str(base) + ".xml"))
            with self._lock:
                self.state.update_gave_up(
                    f"service:{proto}", gave_up,
                    [host for host in targets if host not in set(gave_up)],
                )
            if gave_up:
                self.sink.emit("hosts_gave_up", stage="service", proto=proto,
                               hosts=gave_up, count=len(gave_up))
        self._record_coverage(base.name + ".xml", proto, "enrichment",
                              targets, pspec, ok)
        rows = nmaprun.services(Path(str(base) + ".xml")) if ok else []
        for row in rows:
            self.sink.emit("service", stage="service", confirm=False,
                           **{k: row[k] for k in ("ip", "port", "proto", "service", "product", "version")})
        return first_seconds + r["seconds"], rows, ok


    def _probe_protocol(self, ip, proto, ports, sp, confirm, retries=None, tag="",
                        isolate=False):
        """Probe one protocol per Nmap process.

        Mixed ``-sS -sU`` service scans can turn TCP ports proven open by the sweep into
        filtered/no-response on Windows. Keeping protocol ownership separate also lets TCP
        retain ``--version-all`` without applying that noisy intensity to UDP.
        """
        pspec = ("T:" if proto == "tcp" else "U:") + ",".join(map(str, ports))
        args = self._probe_args(proto, pspec, sp, retries)
        args.append(ip)
        suffix = tag or proto
        base = self.out / f"stage3-{ip.replace('.', '_')}-{suffix}{'-confirm' if confirm else ''}"
        r = self._nmap("service", args, base, fatal=not isolate, targets=[ip])
        ok = not r.get("stopped") and r["rc"] == 0
        first_seconds = 0.0   # 재시도가 있었을 때만 채워진다(아래).
        # UDP 식별이 죽었을 때 한 번만 다른 nsock 엔진으로 다시 시도한다.
        # nsock 은 epoll → kqueue → poll → iocp → select 순으로 고르므로(nsock_engines.c)
        # Windows 기본은 poll 이다. nmap#3138 의 poll 결함은 7.98 에서 고쳐졌지만, 같은
        # 실패가 또 나면 그 수정이 불완전하거나 다른 경로라는 뜻이라 유지관리자가 제시한
        # 우회책(select/iocp)을 그대로 쓴다. poll 을 명시하는 것은 기본값 재지정이라 무의미하다.
        if not ok and not r.get("stopped") and proto == "udp" and not self.state.stopped():
            retry_started = time.time()
            failed_execution_id = r.get("execution_id")
            first_seconds = r.get("seconds") or 0   # 묶음 경로와 같은 이유(단계 소요 합산)
            # 묶음 경로와 **같은 규칙**이다 - 같은 -oA 를 쓰면 nmap 이 시작하자마자 첫
            # 실행의 산출물을 잘라 버린다. 워치독이 끊은 뒤 복구해 둔 관측이 그때 사라지고,
            # 재시도까지 실패하면 되찾은 것만 잃는다. 한 곳만 고치면 경로에 따라 결과가
            # 달라지므로 여기도 임시 base 로 돌린다.
            alt_base = nmaprun.retry_base(base)
            r = self._nmap("service", ["--nsock-engine", _UDP_RETRY_ENGINE] + args, alt_base,
                           fatal=not isolate, targets=[ip])
            ok = (not r.get("stopped") and r["rc"] == 0
                  and nmaprun.xml_usable(alt_base))
            if ok:
                nmaprun.adopt_artifacts(alt_base, base)
            else:
                nmaprun.discard_artifacts(alt_base)
            self.sink.emit(
                "service_retry", stage="service", proto=proto, ip=ip, hosts=[ip],
                ports=list(ports), port_spec=pspec, engine=_UDP_RETRY_ENGINE,
                reason="udp_nsock_engine_fallback",
                outcome="recovered" if ok else "stopped" if r.get("stopped") else "failed",
                recovered=ok, seconds=round(max(time.time() - retry_started, 0), 2),
                rc=r.get("rc"), recovery_of_execution_id=failed_execution_id,
                execution_id=r.get("execution_id"),
            )
        if ok:
            gave_up = nmaprun.timed_out(Path(str(base) + ".xml"))
            with self._lock:
                self.state.update_gave_up(
                    f"service:{proto}", gave_up, [] if gave_up else [ip])
            if gave_up:
                self.sink.emit("hosts_gave_up", stage="service", proto=proto,
                               hosts=gave_up, count=len(gave_up))
        # 역할은 실행 종류가 정한다. 포트 재스캔은 stage3 가 **유일한** 관측이라 authority 이고,
        # 전체 스캔은 sweep 이 이미 개폐를 확정했으므로 stage3 는 enrichment 다. 이걸 파일
        # 이름으로 추측하면 완결된 sweep 의 권한을 stage3 타임아웃 하나가 빼앗는다.
        role = ("authority" if (self.spec.rescan_units or self.spec.targets_ports)
                else "enrichment")
        self._record_coverage(base.name + ".xml", proto, role, [ip], pspec, ok)
        rows = nmaprun.services(Path(str(base) + ".xml")) if ok else []
        for row in rows:
            self.sink.emit("service", stage="service", confirm=confirm,
                           **{k: row[k] for k in ("ip", "port", "proto", "service", "product", "version")})
        return first_seconds + r["seconds"], rows, ok

    def _split_units(self, proto, ports, tag):
        """**실패한 뒤에만** 쪼갤 단위. 정상 경로는 묶어서 한 프로세스로 돌린다.

        무조건 포트별로 나누면 프로세스가 폭증한다. UDP 무응답 포트는 nmap 이 ``open|filtered``
        로 보고하고 ``nmaprun.open_ports()`` 가 그것도 open_map 에 넣으므로, 방화벽이 조용히
        버리는 대역에서는 스캔한 포트가 **전부** 후보가 된다 — 기본 27포트 × /24 면 수천 개
        프로세스다. 고치려던 '안 끝남'을 오히려 악화시킨다.

        그래서 순서를 뒤집는다. 묶어서 한 번 돌리고, **그 실행이 비정상 종료했을 때만** 쪼갠다.
        건강한 실행은 프로세스 하나로 끝나고, 죽는 실행에서만 피해를 포트 단위로 줄인다.

        쪼갤 때도 상한을 둔다. 죽은 실행이 포트를 많이 물고 있으면 그만큼 프로세스가 늘어나는
        건 마찬가지라, 상한을 넘으면 쪼개지 않고 그 실행 전체를 저하로 남긴다.
        """
        if proto != "udp" or len(ports) <= 1 or len(ports) > _MAX_SPLIT_UNITS:
            return []
        return [([port], f"{tag}{port}") for port in ports]

    def _probe_host(self, ip, m, sp, tag="", isolate_failures=False):
        """Probe all present protocols.

        ``isolate_failures`` 는 stage3 가 enrichment 인 전체 스캔에서만 켠다. 그때 식별
        프로세스 하나가 죽는 것은 '이 포트의 부가 정보를 못 얻었다'는 뜻이지 '포트 관측이
        틀렸다'는 뜻이 아니다. 그런데도 지금까지는 그 하나가 호스트 전체, 나아가 stage 전체를
        중단시켜 **뒤따르는 호스트가 통째로 식별되지 못했다** — 사용자가 겪은 'UDP 가 오류
        내며 안 끝남'의 실제 지점이다.

        저하된 호스트는 service_done 에 넣지 않지만, 그것으로 **재개가 되지는 않는다** —
        errors=0 이라 job 이 done 으로 마감되고 /resume 은 is_done 을 거절한다. 다시 얻으려면
        해당 발견을 골라 타겟 재스캔을 돌려야 한다(발견 관리 → 재스캔).

        재스캔에서는 stage3 가 유일한 폐쇄 근거이므로 이 격리를 켜지 않는다. 거기서는 실패가
        곧 '판단할 수 없음'이고, 그대로 권위를 박탈해야 한다.
        """
        seconds, rows, degraded = 0.0, [], False
        for proto in ("tcp", "udp"):
            ports = m.get(proto, [])
            if not ports:
                continue
            unit_tag = tag or proto
            elapsed, found, ok = self._probe_unit(ip, proto, ports, sp, unit_tag, isolate_failures)
            seconds += elapsed
            rows.extend(found)
            if ok:
                continue
            # 중지는 저하가 아니다 — 사용자가 멈춘 것이므로 어떤 모드에서도 즉시 끝낸다.
            if self.state.stopped() or not isolate_failures:
                return seconds, rows, False
            # 묶음이 죽었다 — 이제서야 포트별로 쪼개 피해를 줄인다. 정상 경로는 여기 오지 않는다.
            units = self._split_units(proto, ports, unit_tag)
            # 묶음이 죽은 시점에 이미 저하다. 쪼개서 **전부** 되살렸을 때만 취소한다 —
            # 쪼갤 대상이 없으면(포트 1개, 상한 초과) 그대로 저하로 남아야 한다.
            recovered = 0
            failed_ports = []
            for unit_ports, split_tag in units:
                elapsed, found, ok = self._probe_unit(
                    ip, proto, unit_ports, sp, split_tag, isolate_failures)
                seconds += elapsed
                rows.extend(found)
                if self.state.stopped():
                    return seconds, rows, False
                recovered += 1 if ok else 0
                if not ok:
                    failed_ports.extend(unit_ports)
            if units:
                self.sink.emit(
                    "service_split", stage="service", ip=ip, hosts=[ip], proto=proto,
                    ports=list(ports), port_spec=("T:" if proto == "tcp" else "U:")
                    + ",".join(map(str, ports)), units=len(units),
                    recovered_units=recovered, failed_units=len(units) - recovered,
                    reason="grouped_service_probe_failed",
                    outcome="recovered" if recovered == len(units) else "degraded",
                    recovered=recovered == len(units),
                )
            if not units or recovered < len(units):
                degraded = True
                failed_ports = failed_ports if units else list(ports)
                self.sink.emit(
                    "service_degraded", stage="service", ip=ip, hosts=[ip], proto=proto,
                    ports=list(ports), failed_ports=failed_ports,
                    port_spec=("T:" if proto == "tcp" else "U:")
                    + ",".join(map(str, ports)), units=len(units),
                    recovered_units=recovered, failed_units=(len(units) - recovered)
                    if units else len(ports), reason="service_probe_not_fully_recovered",
                    message="서비스 프로브가 일부 또는 전부 완료되지 않았습니다.",
                )
        if degraded:
            # stage 와 job 은 계속 간다 — 산출물이 비면 artifact_report 가 enrichment_missing
            # 으로 잡아 done + nse_degraded 가 되고, 폐쇄 권위는 sweep 이 그대로 쥔다.
            return seconds, rows, False
        return seconds, rows, True

    def _probe_unit(self, ip, proto, ports, sp, unit_tag, isolate):
        """한 단위(포트 묶음 또는 포트 하나)를 base + 필요 시 confirm 까지 돌린다."""
        seconds, rows = 0.0, []
        elapsed, found, ok = self._probe_protocol(
            ip, proto, ports, sp, confirm=False, tag=unit_tag, isolate=isolate)
        seconds += elapsed
        rows.extend(found)
        if not ok:
            return seconds, rows, False
        if sp.confirm and not found:
            elapsed, confirmed, ok = self._probe_protocol(
                ip, proto, ports, sp, confirm=True, retries=6, tag=unit_tag, isolate=isolate)
            seconds += elapsed
            rows.extend(confirmed)
            if not ok:
                return seconds, rows, False
        return seconds, rows, True

    def _probe_hosts(self, pending, targets, sp, isolate, mark_done=True, activity=None):
        """호스트들을 **동시에** 식별한다. 반환: (초, rows).

        이 단계는 nmap 프로세스마다 타깃이 1개라 nmap 자신의 호스트 병렬성(--min-hostgroup)을
        쓸 수 없다. 직렬로 두면 소요가 호스트 수에 그대로 비례한다 - /24 한 대역이면 프로세스
        수백 개를 하나씩 세우고 기다리는 셈이고, 호스트당 상한을 걸어 둔 만큼 느린 호스트의
        대기시간까지 그대로 더해진다.

        닫힘 권한이 걸린 재스캔(``isolate=False``)은 1 로 강제한다. 거기서는 실패가 곧
        '판단할 수 없음'이라 그 자리에서 멈춰야 하는데, 여러 개를 띄워 두면 이미 시작한
        것들의 처리가 애매해진다 - 권한 경로에 애매함을 만들지 않는다.

        ``mark_done`` 은 이 호출이 그 호스트의 **모든** 프로토콜을 덮을 때만 켠다. 배치
        경로는 프로토콜마다 따로 부르므로, 여기서 찍으면 TCP 만 끝낸 호스트가 UDP 식별
        실패와 무관하게 '완료'로 남는다 - 재개가 그 호스트를 건너뛴다.
        """
        workers = max(1, int(sp.workers)) if isolate else 1
        pending = list(pending)
        total_hosts = len(pending)
        completed_hosts = 0
        secs, rows = 0.0, []
        probed, failed = set(), set()
        for group in _batches(pending, workers):
            if self.state.stopped():
                return secs, rows, probed, failed
            if activity:
                batch = activity["batch"]
                batch_total = activity["batch_total"]
                fraction = completed_hosts / total_hosts if total_hosts else 1.0
                within = (activity.get("phase_start", 0.0)
                          + fraction * activity.get("phase_span", 1.0))
                self.sink.emit(
                    "stage_activity", stage=activity["stage"],
                    percent=round(((batch - 1) + within) / batch_total * 100, 1),
                    batch=batch, batch_total=batch_total,
                    current_hosts=list(group[:8]), current_host_count=len(group),
                    completed_hosts=completed_hosts, total_hosts=total_hosts,
                )
            group_started = time.time()
            if len(group) == 1:
                done = [(group[0], *self._probe_host(group[0], targets[group[0]], sp,
                                                     isolate_failures=isolate))]
            else:
                with ThreadPoolExecutor(max_workers=len(group)) as pool:
                    futures = [(ip, pool.submit(self._probe_host, ip, targets[ip], sp,
                                                isolate_failures=isolate)) for ip in group]
                    done = [(ip, *future.result()) for ip, future in futures]
            # 호스트별 묶음도 **동시에** 돈다 - 묶음 경로와 같은 이유로 벽시계로 잰다.
            # 각 호스트의 소요를 더하면 16대가 10분씩 걸린 묶음이 160분으로 남는다.
            secs += round(max(time.time() - group_started, 0.0), 2)
            # 상태 변경은 여기서만 한다 - 순서를 고정해야 재개·이벤트가 결정적으로 남는다.
            for ip, _elapsed, found, ok in done:
                rows.extend(found)
                probed.add(ip)
                if not ok:
                    failed.add(ip)
                    # 격리 모드에서는 이 호스트만 건너뛰고 나머지 호스트의 식별을 계속한다.
                    # 예전에는 여기서 stage 를 통째로 중단해, nmap 하나가 죽으면 뒤따르는
                    # 호스트가 전부 식별되지 못한 채 실행이 끝났다.
                    if not isolate or self.state.stopped():
                        return secs, rows, probed, failed
                    continue
                if mark_done:
                    self.state.mark_service_done(ip)
            completed_hosts += len(done)
            if activity:
                batch = activity["batch"]
                batch_total = activity["batch_total"]
                fraction = completed_hosts / total_hosts if total_hosts else 1.0
                within = (activity.get("phase_start", 0.0)
                          + fraction * activity.get("phase_span", 1.0))
                self.sink.emit(
                    "stage_activity", stage=activity["stage"],
                    percent=round(((batch - 1) + within) / batch_total * 100, 1),
                    batch=batch, batch_total=batch_total,
                    current_hosts=[], current_host_count=0,
                    completed_hosts=completed_hosts, total_hosts=total_hosts,
                )
            self._save()
        return secs, rows, probed, failed

    def _service(self):
        """타겟 포트 재스캔의 식별 단계 — 전체 스캔은 배치 안에서 식별까지 끝낸다."""
        sp = self.spec.service
        targets = {ip: m for ip, m in self.open_map.items() if m.get("tcp") or m.get("udp")}
        self.sink.emit("stage_start", stage="service", hosts=len(targets))
        # targets_ports 재스캔은 stage3 가 유일한 폐쇄 근거다 — 거기서는 실패를 격리하지
        # 않는다. 전체 스캔에서는 sweep 이 이미 개방 여부의 권위를 쥐고 있으므로 식별
        # 실패는 enrichment 저하로만 남긴다.
        isolate = not self.spec.targets_ports
        pending = [ip for ip in sorted(targets, key=nmaprun._ipkey)
                   if not self.state.service_done(ip)]
        secs, rows, _probed, _failed = self._probe_hosts(pending, targets, sp, isolate)
        if self.state.stopped():
            self.sink.emit("stage_done", stage="service", seconds=round(secs, 2),
                           counts={"stopped": True})
            return
        self.counts["services"] = len(rows)
        self.sink.emit("stage_done", stage="service", seconds=round(secs, 2),
                       counts={"services": len(rows)})
        return True

    # ── 발견(IP:포트)별 개별 재스캔 — 항목마다 nmap 1개(그 ip·그 포트만) ──
    def _rescan_units(self):
        sp = self.spec.service
        units = self.spec.rescan_units or []
        self.sink.emit("stage_start", stage="service", hosts=len(units))
        secs, nsvc = 0.0, 0
        for u in units:
            if self.state.stopped():
                self.sink.emit("stage_done", stage="service", seconds=round(secs, 2), counts={"stopped": True})
                return
            ip, port, proto = str(u["ip"]), int(u["port"]), u.get("proto", "tcp")
            key = f"{ip}|{port}|{proto}"
            if self.state.service_done(key):
                continue
            m = {"udp": [port]} if proto == "udp" else {"tcp": [port]}
            tag = f"{proto}{port}"
            s1, rows, ok = self._probe_host(ip, m, sp, tag=tag)
            secs += s1
            nsvc += len(rows)
            if not ok:
                return False
            self.state.mark_service_done(key)
            self._save()
        self.counts["services"] = nsvc
        self.sink.emit("stage_done", stage="service", seconds=round(secs, 2), counts={"services": nsvc})
        return True

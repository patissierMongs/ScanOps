"""단계 파이프라인 — 발견 → TCP 찾기 → UDP 찾기 → 서비스 probe.

각 단계가 다음 단계 입력을 좁힌다(대역 → live → open → service). 이벤트 emit +
run-state 재개 + 중지. 재스캔(targets_ports)이면 발견·찾기를 건너뛰고 서비스 probe 만.
"""
from __future__ import annotations

import time
from pathlib import Path

from . import nmaprun
from .spec import (DEFAULT_MAX_PARALLELISM, DEFAULT_MIN_HOSTGROUP,
                   DEFAULT_NSE_SCRIPT_TIMEOUT, DISCOVERY_PA, DISCOVERY_PS)
from .state import RunState


# UDP 식별이 죽었을 때 한 번 갈아 끼울 nsock 엔진. nmap#3138 의 유지관리자 우회책이며
# select 는 동시 소켓 수에 제약이 있지만, UDP 식별은 이미 열린 포트 하나만 다루므로 무해하다.
_UDP_RETRY_ENGINE = "select"
# 실패한 UDP 묶음을 포트별로 쪼갤 때의 상한. 넘으면 쪼개지 않고 그 실행을 저하로 남긴다 —
# 죽은 실행이 포트를 많이 물고 있으면 쪼개는 것 자체가 프로세스 폭증이 된다.
_MAX_SPLIT_UNITS = 32


def _batches(items, size):
    size = max(1, size)
    return [items[i:i + size] for i in range(0, len(items), size)]


class Pipeline:
    def __init__(self, spec, sink, nmap):
        self.spec = spec
        self.sink = sink
        self.nmap = nmap
        self.out = Path(spec.out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.state = RunState(self.out / "run-state.json")
        self.counts = {"live": 0, "open_tcp": 0, "open_udp": 0, "services": 0, "errors": 0}
        self.open_map = self.state.get("open_map") or {}

    # ── 공통 ──
    def _nmap(self, stage, args, base, fatal=True) -> dict:
        """``fatal=False`` 면 rc!=0 을 기록만 하고 counts["errors"] 를 올리지 않는다.

        run() 은 errors 로 job status 를 정하므로, 격리된 enrichment 실패까지 여기서 세면
        실패를 격리한 의미가 없어진다 — 실행 전체가 그대로 failed 가 된다.
        """
        r = nmaprun.run(self.nmap, args, base, sudo_mode=self.spec.sudo,
                        progress=lambda p: self.sink.emit("stage_progress", stage=stage, percent=p),
                        stop_requested=self.state.stopped)
        if r.get("stopped"):
            self.sink.emit(
                "stage_done", stage=stage, seconds=r["seconds"], counts={"stopped": True},
            )
        elif r["rc"] != 0:
            if fatal:
                self.counts["errors"] += 1
            self.sink.emit("error", stage=stage, rc=r["rc"], fatal=fatal,
                           cmd=" ".join(map(str, r["cmd"])))
        return r

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

    def _tcp_scan_flag(self) -> str:
        return {"syn": "-sS", "connect": "-sT"}[self.spec.tcp.scan_type]

    # ── 진입 ──
    def run(self) -> dict:
        t0 = time.time()
        self.sink.emit("job_start", job_id=self.spec.job_id, targets=self.spec.targets,
                       rescan=bool(self.spec.targets_ports or self.spec.rescan_units))
        if self.spec.rescan_units:
            # 발견(IP:포트)별 개별 재스캔 — 항목마다 nmap 1개(그 ip·그 포트만).
            if self.spec.service.enabled and not self.state.stopped():
                self._rescan_units()
        else:
            if self.spec.targets_ports:
                for ip, ports in self.spec.targets_ports.items():
                    self.open_map.setdefault(ip, {})["tcp"] = sorted({int(p) for p in ports})
                self._save()
            else:
                live = self._discovery()
                if live and not self.state.stopped() and self.counts["errors"] == 0:
                    if self.spec.tcp.enabled and not self.state.done("tcp"):
                        ok = self._sweep("tcp", live)
                        if ok and not self.state.stopped():
                            self.state.mark_done("tcp")
                        self._save()
                    if (self.counts["errors"] == 0 and self.spec.udp.enabled
                            and not self.state.done("udp") and not self.state.stopped()):
                        ok = self._sweep("udp", live)
                        if ok and not self.state.stopped():
                            self.state.mark_done("udp")
                        self._save()
            if self.counts["errors"] == 0 and self.spec.service.enabled and not self.state.stopped():
                self._service()
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
        args = ["-sn", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", sp.timing,
                "--reason", "--min-hostgroup", str(DEFAULT_MIN_HOSTGROUP),
                "--max-retries", str(sp.max_retries),
                "--max-parallelism", str(DEFAULT_MAX_PARALLELISM)]
        args += self._exclude_args()
        args += list(self.spec.targets)
        base = self.out / "stage0-discovery"
        r = self._nmap("discovery", args, base)
        if r.get("stopped") or r["rc"] != 0:
            return []
        live = nmaprun.hosts_up(Path(str(base) + ".xml"))
        self.counts["live"] = len(live)
        self.sink.emit("hosts_up", stage="discovery", hosts=live, count=len(live))
        self.sink.emit("stage_done", stage="discovery", seconds=r["seconds"], counts={"live": len(live)})
        self.state.set("live", live)
        self.state.mark_done("discovery")
        self.state.save()
        return live

    # ── Stage 1/2: TCP·UDP 찾기 ──
    def _sweep(self, proto, live) -> bool:
        sp = self.spec.tcp if proto == "tcp" else self.spec.udp
        self.sink.emit("stage_start", stage=proto, hosts=len(live), ports=sp.ports)
        secs, total_open = 0.0, 0
        for bi, batch in enumerate(_batches(live, self.spec.batch_size)):
            if self.state.stopped():
                self.sink.emit("stage_done", stage=proto, seconds=round(secs, 2), counts={"stopped": True})
                return
            args = [("-sU" if proto == "udp" else self._tcp_scan_flag()),
                    "-Pn", "-n", "--open",
                    sp.timing, "--reason", "--max-retries", str(sp.max_retries)]
            if proto == "tcp":
                args += ["--min-hostgroup", str(DEFAULT_MIN_HOSTGROUP)]
                if self.spec.tcp.scan_type == "syn":
                    args.append("--defeat-rst-ratelimit")
                args += ["--max-parallelism", str(DEFAULT_MAX_PARALLELISM)]
                if sp.min_rate > 0:
                    args += ["--min-rate", str(sp.min_rate)]
            args += ["-p", sp.ports]
            args += self._exclude_args()
            args += batch
            base = self.out / f"stage-{proto}-b{bi}"
            r = self._nmap(proto, args, base)
            secs += r["seconds"]
            if r.get("stopped") or r["rc"] != 0:
                return False
            found = nmaprun.open_ports(Path(str(base) + ".xml"), proto=proto)
            for ip, ports in found.items():
                self.open_map.setdefault(ip, {})[proto] = ports
                total_open += len(ports)
                self.sink.emit("ports_open", stage=proto, ip=ip, ports=ports)
            self._save()
        self.counts["open_tcp" if proto == "tcp" else "open_udp"] = total_open
        nhosts = sum(1 for m in self.open_map.values() if m.get(proto))
        self.sink.emit("stage_done", stage=proto, seconds=round(secs, 2),
                       counts={"open_ports": total_open, "hosts": nhosts})
        return True

    # ── Stage 3: 서비스 probe (호스트별 열린 포트에만) ──
    def _probe_protocol(self, ip, proto, ports, sp, confirm, retries=None, tag="",
                        isolate=False):
        """Probe one protocol per Nmap process.

        Mixed ``-sS -sU`` service scans can turn TCP ports proven open by the sweep into
        filtered/no-response on Windows. Keeping protocol ownership separate also lets TCP
        retain ``--version-all`` without applying that noisy intensity to UDP.
        """
        pspec = ("T:" if proto == "tcp" else "U:") + ",".join(map(str, ports))
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
        args += ["--open", "--reason", sp.timing, "--max-retries",
                 str(retries if retries is not None else sp.max_retries), "-p", pspec]
        # NSE 는 TCP probe 에만. 발견에 반영되는 스크립트가 전부 TCP 이고(UDP 쪽 출력은 저장만 되고
        # 읽는 코드가 없다), 출발지 포트를 bind 하는 UDP 스크립트는 스캔 호스트의 서비스와 충돌해
        # (ike-version↔IKEEXT 의 UDP 500) NSE 정리 실패로 그 실행을 통째로 못 믿게 만든다.
        if sp.nse and proto == "tcp":
            args += ["--script", ",".join(sp.nse),
                     "--script-timeout", DEFAULT_NSE_SCRIPT_TIMEOUT]
        args += self._exclude_args()
        args.append(ip)
        suffix = tag or proto
        base = self.out / f"stage3-{ip.replace('.', '_')}-{suffix}{'-confirm' if confirm else ''}"
        r = self._nmap("service", args, base, fatal=not isolate)
        ok = not r.get("stopped") and r["rc"] == 0
        # UDP 식별이 죽었을 때 한 번만 다른 nsock 엔진으로 다시 시도한다.
        # nsock 은 epoll → kqueue → poll → iocp → select 순으로 고르므로(nsock_engines.c)
        # Windows 기본은 poll 이다. nmap#3138 의 poll 결함은 7.98 에서 고쳐졌지만, 같은
        # 실패가 또 나면 그 수정이 불완전하거나 다른 경로라는 뜻이라 유지관리자가 제시한
        # 우회책(select/iocp)을 그대로 쓴다. poll 을 명시하는 것은 기본값 재지정이라 무의미하다.
        if not ok and not r.get("stopped") and proto == "udp" and not self.state.stopped():
            self.sink.emit("service_retry", stage="service", ip=ip, engine=_UDP_RETRY_ENGINE)
            r = self._nmap("service", ["--nsock-engine", _UDP_RETRY_ENGINE] + args, base,
                           fatal=not isolate)
            ok = not r.get("stopped") and r["rc"] == 0
        rows = nmaprun.services(Path(str(base) + ".xml")) if ok else []
        for row in rows:
            self.sink.emit("service", stage="service", confirm=confirm,
                           **{k: row[k] for k in ("ip", "port", "proto", "service", "product", "version")})
        return r["seconds"], rows, ok

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
            if units:
                self.sink.emit("service_split", stage="service", ip=ip, proto=proto,
                               units=len(units))
            # 묶음이 죽은 시점에 이미 저하다. 쪼개서 **전부** 되살렸을 때만 취소한다 —
            # 쪼갤 대상이 없으면(포트 1개, 상한 초과) 그대로 저하로 남아야 한다.
            recovered = 0
            for unit_ports, split_tag in units:
                elapsed, found, ok = self._probe_unit(
                    ip, proto, unit_ports, sp, split_tag, isolate_failures)
                seconds += elapsed
                rows.extend(found)
                if self.state.stopped():
                    return seconds, rows, False
                recovered += 1 if ok else 0
            if not units or recovered < len(units):
                degraded = True
        if degraded:
            # stage 와 job 은 계속 간다 — 산출물이 비면 artifact_report 가 enrichment_missing
            # 으로 잡아 done + nse_degraded 가 되고, 폐쇄 권위는 sweep 이 그대로 쥔다.
            self.sink.emit("service_degraded", stage="service", ip=ip)
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

    def _service(self):
        sp = self.spec.service
        targets = {ip: m for ip, m in self.open_map.items() if m.get("tcp") or m.get("udp")}
        self.sink.emit("stage_start", stage="service", hosts=len(targets))
        secs, nsvc = 0.0, 0
        for ip in sorted(targets, key=nmaprun._ipkey):
            if self.state.stopped():
                self.sink.emit("stage_done", stage="service", seconds=round(secs, 2), counts={"stopped": True})
                return
            if self.state.service_done(ip):
                continue
            # targets_ports 재스캔은 stage3 가 유일한 폐쇄 근거다 — 거기서는 실패를 격리하지
            # 않는다. 전체 스캔에서는 sweep 이 이미 개방 여부의 권위를 쥐고 있으므로 식별
            # 실패는 enrichment 저하로만 남긴다.
            isolate = not self.spec.targets_ports
            s1, rows, ok = self._probe_host(ip, targets[ip], sp, isolate_failures=isolate)
            secs += s1
            nsvc += len(rows)
            if not ok:
                # 격리 모드에서는 이 호스트만 건너뛰고 나머지 호스트의 식별을 계속한다.
                # 예전에는 여기서 stage 를 통째로 중단해, nmap 하나가 죽으면 뒤따르는
                # 호스트가 전부 식별되지 못한 채 실행이 끝났다.
                if not isolate or self.state.stopped():
                    return False
                continue
            self.state.mark_service_done(ip)
            self._save()
        self.counts["services"] = nsvc
        self.sink.emit("stage_done", stage="service", seconds=round(secs, 2), counts={"services": nsvc})
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

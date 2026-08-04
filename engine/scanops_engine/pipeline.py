"""단계 파이프라인 — 발견 → TCP 찾기 → UDP 찾기 → 서비스 probe.

각 단계가 다음 단계 입력을 좁힌다(대역 → live → open → service). 이벤트 emit +
run-state 재개 + 중지. 재스캔(targets_ports)이면 발견·찾기를 건너뛰고 서비스 probe 만.
"""
from __future__ import annotations

import time
from pathlib import Path

from . import nmaprun
from .state import RunState


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
    def _nmap(self, stage, args, base) -> dict:
        r = nmaprun.run(self.nmap, args, base, sudo_mode=self.spec.sudo,
                        progress=lambda p: self.sink.emit("stage_progress", stage=stage, percent=p),
                        stop_requested=self.state.stopped)
        if r.get("stopped"):
            self.sink.emit(
                "stage_done", stage=stage, seconds=r["seconds"], counts={"stopped": True},
            )
        elif r["rc"] != 0:
            self.counts["errors"] += 1
            self.sink.emit("error", stage=stage, rc=r["rc"], cmd=" ".join(map(str, r["cmd"])))
        return r

    def _save(self):
        self.state.set("open_map", self.open_map)
        self.state.save()

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
        args = ["-sn", "-n"]
        for ex in self.spec.exclude:
            args += ["--exclude", ex]
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
            args = [("-sU" if proto == "udp" else "-sS"), "-Pn", "-n", "--open", sp.timing, "-p", sp.ports]
            if proto == "tcp":
                args += ["--min-rate", str(sp.min_rate), "--max-retries", str(sp.max_retries)]
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
    def _probe_protocol(self, ip, proto, ports, sp, confirm, retries=None, tag=""):
        """Probe one protocol per Nmap process.

        Mixed ``-sS -sU`` service scans can turn TCP ports proven open by the sweep into
        filtered/no-response on Windows. Keeping protocol ownership separate also lets TCP
        retain ``--version-all`` without applying that noisy intensity to UDP.
        """
        pspec = ("T:" if proto == "tcp" else "U:") + ",".join(map(str, ports))
        args = ["-sV", "-Pn", "-n", "--reason"]
        if proto == "tcp":
            args.append("-sS")
        else:
            args.append("-sU")
        # --version-all(강도 9)은 TCP 에만 — 수다스러운/증폭형 UDP 서비스에서
        # 거대·비정상 응답으로 nmap 이 fatal 종료될 위험이 크고 식별 이득은 미미하다.
        if sp.version_all and proto == "tcp":
            args.append("--version-all")
        elif sp.version_light:
            args.append("--version-light")
        args += ["--max-retries", str(retries if retries is not None else sp.max_retries), "-p", pspec]
        if sp.nse:
            args += ["--script", ",".join(sp.nse)]
        args.append(ip)
        suffix = tag or proto
        base = self.out / f"stage3-{ip.replace('.', '_')}-{suffix}{'-confirm' if confirm else ''}"
        r = self._nmap("service", args, base)
        ok = not r.get("stopped") and r["rc"] == 0
        rows = nmaprun.services(Path(str(base) + ".xml")) if ok else []
        for row in rows:
            self.sink.emit("service", stage="service", confirm=confirm,
                           **{k: row[k] for k in ("ip", "port", "proto", "service", "product", "version")})
        return r["seconds"], rows, ok

    def _probe_host(self, ip, m, sp, tag=""):
        """Probe all present protocols; completion is atomic at the host/unit boundary."""
        seconds, rows = 0.0, []
        for proto in ("tcp", "udp"):
            ports = m.get(proto, [])
            if not ports:
                continue
            proto_tag = tag or proto
            elapsed, found, ok = self._probe_protocol(
                ip, proto, ports, sp, confirm=False, tag=proto_tag,
            )
            seconds += elapsed
            rows.extend(found)
            if not ok:
                return seconds, rows, False
            # Confirm independently: a TCP result must not suppress an empty UDP retry.
            if sp.confirm and not found:
                elapsed, confirmed, ok = self._probe_protocol(
                    ip, proto, ports, sp, confirm=True, retries=6, tag=proto_tag,
                )
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
            s1, rows, ok = self._probe_host(ip, targets[ip], sp)
            secs += s1
            nsvc += len(rows)
            if not ok:
                return False
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

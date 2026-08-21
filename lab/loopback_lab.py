#!/usr/bin/env python3
"""Offline multi-host loopback lab for ScanOps staged-scan testing.

One process binds distinct TCP and UDP listeners to 127.0.0.2-127.0.0.6.
This is intentionally a socket lab, not a network-emulation lab: it validates
host/port grouping, union probes, service probes, and scan history without
requiring Docker, WSL, or Internet access.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import socketserver
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class HostProfile:
    ip: str
    name: str
    tcp: tuple[int, ...]
    udp: tuple[int, ...]


HOSTS: tuple[HostProfile, ...] = (
    HostProfile("127.0.0.2", "alpha", (8022, 8080, 8443, 4444), (1053, 1161)),
    HostProfile("127.0.0.3", "bravo", (8022, 8080, 8443, 3333), (1053, 5060)),
    HostProfile("127.0.0.4", "charlie", (8022, 8080, 8888), (1161, 11211)),
    HostProfile("127.0.0.5", "delta", (8080, 8443, 9999), (1053, 11211)),
    HostProfile("127.0.0.6", "echo", (8022, 8080, 8443), (5060,)),
)


def _service_name(port: int, protocol: str) -> str:
    if protocol == "tcp":
        if port == 8022:
            return "ssh"
        if port in (8080, 8443, 8888):
            return "http"
        return "banner"
    if port == 1053:
        return "dns"
    if port == 1161:
        return "snmp-test"
    if port == 5060:
        return "sip"
    if port == 11211:
        return "memcached"
    return "udp-echo"


class _TCPServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


class _UDPServer(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        profile: HostProfile = self.server.profile  # type: ignore[attr-defined]
        port = int(self.server.server_address[1])
        self.request.settimeout(0.5)
        service = _service_name(port, "tcp")
        if service == "ssh":
            self.request.sendall(b"SSH-2.0-OpenSSH_9.6 ScanOps-Lab\r\n")
            return
        if service == "http":
            try:
                self.request.recv(4096)
            except (TimeoutError, socket.timeout):
                pass
            body = f"ScanOps loopback lab: {profile.name} {profile.ip}:{port}\n".encode()
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: ScanOps-Lab/1.0\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            self.request.sendall(response)
            return
        banner = f"SCANOPS-LAB {profile.name} {profile.ip}:{port}\r\n".encode()
        self.request.sendall(banner)


def _dns_response(payload: bytes) -> bytes:
    if len(payload) < 12:
        return b"SCANOPS-LAB-DNS\n"
    transaction_id = payload[:2]
    question_count = payload[4:6]
    return transaction_id + b"\x81\x80" + question_count + b"\x00\x00\x00\x00\x00\x00" + payload[12:]


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, sock = self.request
        profile: HostProfile = self.server.profile  # type: ignore[attr-defined]
        port = int(self.server.server_address[1])
        service = _service_name(port, "udp")
        if service == "dns":
            response = _dns_response(payload)
        elif service == "sip":
            response = (
                b"SIP/2.0 200 OK\r\n"
                b"Server: ScanOps-Lab/1.0\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        elif service == "memcached":
            response = b"STAT version ScanOps-Lab-1.0\r\nEND\r\n"
        else:
            response = f"SCANOPS-LAB-UDP {profile.name} {profile.ip}:{port}\n".encode()
        sock.sendto(response, self.client_address)


class LoopbackLab:
    def __init__(self, hosts: Iterable[HostProfile] = HOSTS) -> None:
        self.hosts = tuple(hosts)
        self._servers: list[socketserver.BaseServer] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        try:
            for profile in self.hosts:
                for port in profile.tcp:
                    try:
                        server = _TCPServer((profile.ip, port), _TCPHandler)
                    except OSError as exc:
                        raise OSError(exc.errno, f"tcp://{profile.ip}:{port}: {exc}") from exc
                    server.profile = profile  # type: ignore[attr-defined]
                    self._servers.append(server)
                for port in profile.udp:
                    try:
                        server = _UDPServer((profile.ip, port), _UDPHandler)
                    except OSError as exc:
                        raise OSError(exc.errno, f"udp://{profile.ip}:{port}: {exc}") from exc
                    server.profile = profile  # type: ignore[attr-defined]
                    self._servers.append(server)
        except OSError:
            for server in self._servers:
                server.server_close()
            self._servers.clear()
            raise

        for server in self._servers:
            protocol = "tcp" if isinstance(server, _TCPServer) else "udp"
            ip, port = server.server_address
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name=f"loopback-lab-{protocol}-{ip}-{port}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
        for server in self._servers:
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()
        self._servers.clear()


def topology() -> dict[str, object]:
    return {
        "target": "127.0.0.2-6",
        "cidr": "127.0.0.0/29",
        "hosts": [asdict(host) for host in HOSTS],
        "tcp_union": sorted({port for host in HOSTS for port in host.tcp}),
        "udp_union": sorted({port for host in HOSTS for port in host.udp}),
    }


def _write_state(path: Path | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "pid": os.getpid(),
        "executable": sys.executable,
        "started_at": time.time(),
        **topology(),
    }
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _check_tcp(host: HostProfile, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host.ip, port), timeout=timeout) as client:
            client.settimeout(timeout)
            if _service_name(port, "tcp") == "http":
                client.sendall(b"GET / HTTP/1.0\r\nHost: scanops-lab\r\n\r\n")
            data = client.recv(512)
            if not data:
                return f"tcp://{host.ip}:{port}: empty response"
    except OSError as exc:
        return f"tcp://{host.ip}:{port}: {exc}"
    return None


def _check_udp(host: HostProfile, port: int, timeout: float) -> str | None:
    payload = b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" if port == 1053 else b"ScanOps lab check"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.sendto(payload, (host.ip, port))
            data, address = client.recvfrom(1024)
            if not data or address[0] != host.ip:
                return f"udp://{host.ip}:{port}: invalid response"
    except OSError as exc:
        return f"udp://{host.ip}:{port}: {exc}"
    return None


def check_lab(timeout: float) -> list[str]:
    failures: list[str] = []
    for host in HOSTS:
        for port in host.tcp:
            failure = _check_tcp(host, port, timeout)
            if failure:
                failures.append(failure)
        for port in host.udp:
            failure = _check_udp(host, port, timeout)
            if failure:
                failures.append(failure)
    return failures


def print_topology() -> None:
    for host in HOSTS:
        tcp = ",".join(map(str, host.tcp))
        udp = ",".join(map(str, host.udp))
        print(f"{host.ip:<11} {host.name:<8} TCP {tcp:<20} UDP {udp}")
    info = topology()
    print(f"TCP union: {','.join(map(str, info['tcp_union']))}")
    print(f"UDP union: {','.join(map(str, info['udp_union']))}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ScanOps Windows multi-IP loopback test lab")
    parser.add_argument("--list", action="store_true", help="print the host and port topology")
    parser.add_argument("--check", action="store_true", help="check every configured TCP/UDP listener")
    parser.add_argument("--timeout", type=float, default=1.5, help="per-listener check timeout in seconds")
    parser.add_argument("--duration", type=float, default=0, help="stop automatically after N seconds")
    parser.add_argument("--state-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--stop-file", type=Path, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list:
        print_topology()
        return 0
    if args.check:
        failures = check_lab(args.timeout)
        if failures:
            print("Loopback lab check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        print(f"Loopback lab check passed: {sum(len(h.tcp) + len(h.udp) for h in HOSTS)} listeners")
        return 0

    stop_event = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)

    lab = LoopbackLab()
    try:
        lab.start()
    except OSError as exc:
        print(f"Cannot start loopback lab: {exc}", file=sys.stderr)
        print("Another process may already own one of the configured IP/ports.", file=sys.stderr)
        return 2

    _write_state(args.state_file)
    print_topology()
    print(f"Loopback lab ready (PID {os.getpid()}). Press Ctrl+C to stop.", flush=True)
    started = time.monotonic()
    try:
        while not stop_event.wait(0.2):
            if args.stop_file and args.stop_file.exists():
                break
            if args.duration > 0 and time.monotonic() - started >= args.duration:
                break
    finally:
        lab.stop()
        if args.state_file:
            args.state_file.unlink(missing_ok=True)
        if args.stop_file:
            args.stop_file.unlink(missing_ok=True)
    print("Loopback lab stopped.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

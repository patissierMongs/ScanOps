"""Standalone scanner script — no ScanOps app import and no real nmap required."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py"
GUI_SCRIPT = Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner_gui.py"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scanops_standalone_scanner", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _args(**kw):
    base = {
        "profile": "basic",
        "scan_type": "",
        "udp": False,
        "tcp_only": False,
        "all_ports": False,
        "ports": "",
        "nse_default": False,
        "scripts": "",
        "no_scripts": False,
        "open_only": False,
        "include_closed": False,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def _fake_nmap(tmp_path: Path) -> Path:
    fake_py = tmp_path / "fake_nmap.py"
    fake_py.write_text(
        r'''
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def stage_from_base(base: Path) -> str:
    for stage in ("tcp_discovery", "tcp_identify", "udp_identify"):
        if base.name.endswith("." + stage):
            return stage
    return "single"


def write_xml(base: Path, stage: str) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    if stage == "tcp_discovery":
        ports = """
        <port protocol="tcp" portid="22"><state state="open"/></port>
        <port protocol="tcp" portid="443"><state state="open"/></port>
        <port protocol="tcp" portid="80"><state state="closed"/></port>
        """
    elif stage == "tcp_identify":
        ports = """
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
        <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
        """
    elif stage == "udp_identify":
        ports = """
        <port protocol="udp" portid="53"><state state="open"/><service name="domain" product="BIND"/></port>
        """
    else:
        ports = """
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
        """
    xml = f"""<?xml version="1.0"?>
<nmaprun scanner="fake">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>{ports}</ports>
  </host>
</nmaprun>
"""
    Path(str(base) + ".xml").write_text(xml, encoding="utf-8")
    Path(str(base) + ".nmap").write_text(f"fake nmap {stage}\n", encoding="utf-8")
    Path(str(base) + ".gnmap").write_text(f"Host: 127.0.0.1 Ports: fake/{stage}\n", encoding="utf-8")


def main() -> int:
    args = sys.argv[1:]
    if "-oA" not in args:
        return 2
    base = Path(args[args.index("-oA") + 1])
    stage = stage_from_base(base)
    log = os.environ.get("FAKE_NMAP_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as fp:
            fp.write(json.dumps({"stage": stage, "args": args}, ensure_ascii=False) + "\n")
    if os.environ.get("FAKE_NMAP_FAIL_STAGE") == stage:
        return int(os.environ.get("FAKE_NMAP_FAIL_CODE", "7"))
    write_xml(base, stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''.lstrip(),
        encoding="utf-8",
    )
    if os.name == "nt":
        fake_cmd = tmp_path / "fake_nmap.cmd"
        fake_cmd.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            encoding="utf-8",
        )
        return fake_cmd
    fake_sh = tmp_path / "fake_nmap"
    fake_sh.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fake_py}" "$@"\n', encoding="utf-8")
    fake_sh.chmod(0o755)
    return fake_sh


def _run_scanner(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    run_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        env=run_env,
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_basic_profile_matches_lightweight_single_run_default():
    scanner = _load_scanner()

    flags = scanner.build_base_flags(_args())

    assert flags == ["-Pn", "-sV", "-T4"]


def test_phase1_profile_matches_precision_single_run_preset():
    scanner = _load_scanner()

    flags = scanner.build_base_flags(_args(profile="phase1"))

    assert flags[:4] == ["-sS", "-sU", "-Pn", "-n"]
    assert "-sV" in flags
    assert "--version-all" in flags
    assert "--open" in flags
    assert flags[flags.index("-p") + 1].startswith("T:1-65535,U:")
    assert "--script" in flags
    assert "http-title" in flags[flags.index("--script") + 1]
    assert "ldap-rootdse" not in flags[flags.index("--script") + 1]


def test_ports_override_profile_port_selection():
    scanner = _load_scanner()

    flags = scanner.build_base_flags(_args(profile="phase1", ports="22,80,443"))

    assert flags[flags.index("-p") + 1] == "22,80,443"


def test_phase1_can_drop_udp_scripts_and_open_filter():
    scanner = _load_scanner()

    flags = scanner.build_base_flags(_args(profile="phase1", tcp_only=True, no_scripts=True, include_closed=True))

    assert "-sU" not in flags
    assert "--open" not in flags
    assert "--script" not in flags
    assert flags[flags.index("-p") + 1] == "T:1-65535"


def test_auto_workflow_builds_discovery_identification_and_udp_commands(tmp_path):
    scanner = _load_scanner()
    args = scanner.parser().parse_args([
        "--dry-run",
        "--nmap",
        "nmap",
        "--output-dir",
        str(tmp_path),
        "--name",
        "auto",
        "127.0.0.1",
    ])

    plan = scanner.create_plan(args)

    assert plan["workflow"] == "auto"
    tcp_discovery = scanner.build_command(plan, 0, "tcp_discovery")
    tcp_identify = scanner.build_command(plan, 0, "tcp_identify", [22, 443])
    udp_identify = scanner.build_command(plan, 0, "udp_identify")
    assert tcp_discovery[tcp_discovery.index("-p") + 1] == "T:1-65535"
    assert tcp_identify[tcp_identify.index("-p") + 1] == "T:22,443"
    assert "--script" in tcp_identify
    assert "http-title" in tcp_identify[tcp_identify.index("--script") + 1]
    assert udp_identify[udp_identify.index("-p") + 1].startswith("U:")
    # 강도 9(--version-all)는 TCP 식별에만. UDP 는 기본 -sV(강도 7) — 수다/증폭 UDP nmap fatal 회피.
    assert "--version-all" in tcp_identify
    assert "--version-all" not in udp_identify
    assert "-sV" in udp_identify


def test_auto_workflow_reads_open_tcp_ports_from_discovery_xml(tmp_path):
    scanner = _load_scanner()
    xml = tmp_path / "scan.tcp_discovery.xml"
    xml.write_text(
        textwrap.dedent(
            """\
            <?xml version="1.0"?>
            <nmaprun>
              <host>
                <ports>
                  <port protocol="tcp" portid="22"><state state="open"/></port>
                  <port protocol="tcp" portid="80"><state state="closed"/></port>
                  <port protocol="udp" portid="53"><state state="open"/></port>
                </ports>
              </host>
            </nmaprun>
            """
        ),
        encoding="utf-8",
    )

    assert scanner.open_ports_from_xml(xml, "tcp") == [22]
    assert scanner.open_ports_from_xml(xml, "udp") == [53]


def test_manifest_recommends_identification_xml_not_discovery_xml(tmp_path):
    scanner = _load_scanner()
    manifest = tmp_path / "scan.manifest.json"
    plan = {
        "manifest_path": str(manifest),
        "state_path": str(tmp_path / "scan.state.json"),
        "runs": [
            {"stage_id": "tcp_discovery", "returncode": 0, "files": [str(tmp_path / "scan.tcp_discovery.xml")]},
            {"stage_id": "tcp_identify", "returncode": 0, "files": [str(tmp_path / "scan.tcp_identify.xml")]},
            {"stage_id": "udp_identify", "returncode": 0, "files": [str(tmp_path / "scan.udp_identify.xml")]},
        ],
    }

    scanner.write_manifest(plan)
    data = scanner.json.loads(manifest.read_text(encoding="utf-8"))

    assert str(tmp_path / "scan.tcp_discovery.xml") in data["all_xml_files"]
    assert str(tmp_path / "scan.tcp_discovery.xml") not in data["import_xml_files"]
    assert str(tmp_path / "scan.tcp_identify.xml") in data["import_xml_files"]
    assert str(tmp_path / "scan.udp_identify.xml") in data["import_xml_files"]


def test_default_auto_workflow_end_to_end_creates_manifest_import_list_and_zip(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)
    output_dir = tmp_path / "out"
    log_path = tmp_path / "fake_nmap.jsonl"

    result = _run_scanner(
        [
            "--nmap",
            str(fake_nmap),
            "--output-dir",
            str(output_dir),
            "--name",
            "auto",
            "--zip",
            "127.0.0.1",
        ],
        env={"FAKE_NMAP_LOG": str(log_path)},
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "TCP 전체 포트 발견" in result.stdout
    assert "발견된 TCP 포트 용도/서비스 식별" in result.stdout
    assert "주요 UDP 서비스 식별" in result.stdout
    manifest = json.loads((output_dir / "auto.manifest.json").read_text(encoding="utf-8"))
    state = json.loads((output_dir / "auto.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "done"
    assert [entry["stage"] for entry in _read_jsonl(log_path)] == ["tcp_discovery", "tcp_identify", "udp_identify"]
    assert (output_dir / "auto.tcp_discovery.xml").exists()
    assert (output_dir / "auto.tcp_identify.xml").exists()
    assert (output_dir / "auto.udp_identify.xml").exists()
    assert str(output_dir / "auto.tcp_discovery.xml") not in manifest["import_xml_files"]
    assert str(output_dir / "auto.tcp_identify.xml") in manifest["import_xml_files"]
    assert str(output_dir / "auto.udp_identify.xml") in manifest["import_xml_files"]
    identify_run = next(run for run in state["runs"] if run["stage_id"] == "tcp_identify")
    assert identify_run["command"][identify_run["command"].index("-p") + 1] == "T:22,443"
    zip_path = output_dir / "auto.scanops.zip"
    assert manifest["zip_path"] == str(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert {"auto.manifest.json", "auto.state.json", "auto.tcp_identify.xml", "auto.udp_identify.xml"} <= names


def test_known_tcp_ports_end_to_end_skips_udp_and_scripts_when_requested(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)
    output_dir = tmp_path / "out"

    result = _run_scanner([
        "--nmap",
        str(fake_nmap),
        "--output-dir",
        str(output_dir),
        "--name",
        "tcp_only",
        "--ports",
        "22,443",
        "--tcp-only",
        "--no-scripts",
        "127.0.0.1",
    ])

    assert result.returncode == 0, result.stderr + result.stdout
    state = json.loads((output_dir / "tcp_only.state.json").read_text(encoding="utf-8"))
    discovery = next(run for run in state["runs"] if run["stage_id"] == "tcp_discovery")
    identify = next(run for run in state["runs"] if run["stage_id"] == "tcp_identify")
    udp = next(run for run in state["runs"] if run["stage_id"] == "udp_identify")
    assert discovery["command"][discovery["command"].index("-p") + 1] == "22,443"
    assert "--script" not in identify["command"]
    assert udp["skipped"] is True
    assert not (output_dir / "tcp_only.udp_identify.xml").exists()


def test_udp_only_port_end_to_end_does_not_run_full_tcp_scan(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)
    output_dir = tmp_path / "out"
    log_path = tmp_path / "fake_nmap.jsonl"

    result = _run_scanner(
        [
            "--nmap",
            str(fake_nmap),
            "--output-dir",
            str(output_dir),
            "--name",
            "udp_only",
            "--ports",
            "U:53",
            "127.0.0.1",
        ],
        env={"FAKE_NMAP_LOG": str(log_path)},
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert [entry["stage"] for entry in _read_jsonl(log_path)] == ["udp_identify"]
    state = json.loads((output_dir / "udp_only.state.json").read_text(encoding="utf-8"))
    tcp_discovery = next(run for run in state["runs"] if run["stage_id"] == "tcp_discovery")
    tcp_identify = next(run for run in state["runs"] if run["stage_id"] == "tcp_identify")
    udp_identify = next(run for run in state["runs"] if run["stage_id"] == "udp_identify")
    assert tcp_discovery["skipped"] is True
    assert tcp_identify["skipped"] is True
    assert udp_identify["command"][udp_identify["command"].index("-p") + 1] == "U:53"
    manifest = json.loads((output_dir / "udp_only.manifest.json").read_text(encoding="utf-8"))
    assert manifest["import_xml_files"] == [str(output_dir / "udp_only.udp_identify.xml")]


def test_resume_after_failed_identification_reuses_successful_discovery(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)
    output_dir = tmp_path / "out"
    log_path = tmp_path / "fake_nmap.jsonl"

    first = _run_scanner(
        [
            "--nmap",
            str(fake_nmap),
            "--output-dir",
            str(output_dir),
            "--name",
            "resume",
            "127.0.0.1",
        ],
        env={"FAKE_NMAP_LOG": str(log_path), "FAKE_NMAP_FAIL_STAGE": "tcp_identify"},
    )
    assert first.returncode == 7, first.stderr + first.stdout
    failed_state = json.loads((output_dir / "resume.state.json").read_text(encoding="utf-8"))
    assert failed_state["status"] == "failed"

    second = _run_scanner(
        [
            "--resume",
            str(output_dir / "resume.state.json"),
            "--nmap",
            str(fake_nmap),
            "--zip",
        ],
        env={"FAKE_NMAP_LOG": str(log_path)},
    )

    assert second.returncode == 0, second.stderr + second.stdout
    assert [entry["stage"] for entry in _read_jsonl(log_path)] == [
        "tcp_discovery",
        "tcp_identify",
        "tcp_identify",
        "udp_identify",
    ]
    resumed_state = json.loads((output_dir / "resume.state.json").read_text(encoding="utf-8"))
    assert resumed_state["status"] == "done"
    assert (output_dir / "resume.scanops.zip").exists()


def test_targets_file_batching_end_to_end_creates_numbered_outputs(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("127.0.0.1\n127.0.0.2\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = _run_scanner([
        "--nmap",
        str(fake_nmap),
        "--output-dir",
        str(output_dir),
        "--name",
        "batch",
        "--targets-file",
        str(targets),
        "--batch-size",
        "1",
        "--tcp-only",
    ])

    assert result.returncode == 0, result.stderr + result.stdout
    manifest = json.loads((output_dir / "batch.manifest.json").read_text(encoding="utf-8"))
    assert (output_dir / "batch.b0000.tcp_identify.xml").exists()
    assert (output_dir / "batch.b0001.tcp_identify.xml").exists()
    assert manifest["import_xml_files"] == [
        str(output_dir / "batch.b0000.tcp_identify.xml"),
        str(output_dir / "batch.b0001.tcp_identify.xml"),
    ]


def test_tcp_only_with_udp_only_ports_is_rejected(tmp_path):
    fake_nmap = _fake_nmap(tmp_path)

    result = _run_scanner([
        "--nmap",
        str(fake_nmap),
        "--output-dir",
        str(tmp_path / "out"),
        "--ports",
        "U:53",
        "--tcp-only",
        "127.0.0.1",
    ])

    assert result.returncode == 2
    assert "TCP 포트" in result.stderr


def test_batching_expands_cidr_without_scanops_dependencies():
    scanner = _load_scanner()

    hosts = scanner.expand_targets(["192.0.2.0/30"], cap=16)
    batches = scanner.make_batches(hosts, 2)

    assert hosts == ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert batches == [["192.0.2.0", "192.0.2.1"], ["192.0.2.2", "192.0.2.3"]]


def test_default_dry_run_prints_auto_workflow_without_installed_nmap(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--dry-run",
            "--nmap",
            "nmap",
            "--output-dir",
            str(tmp_path),
            "--name",
            "dry",
            "127.0.0.1",
        ],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "TCP 전체 포트 발견" in result.stdout
    assert "발견된 TCP 포트 용도/서비스 식별" in result.stdout
    assert "주요 UDP 서비스 식별" in result.stdout
    assert "T:<open TCP ports from previous step>" in result.stdout
    assert "127.0.0.1" in result.stdout
    assert not any(tmp_path.iterdir())


def test_single_workflow_dry_run_keeps_basic_default(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--dry-run",
            "--nmap",
            "nmap",
            "--workflow",
            "single",
            "--profile",
            "basic",
            "--output-dir",
            str(tmp_path),
            "--name",
            "single",
            "127.0.0.1",
        ],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "-Pn -sV -T4" in result.stdout
    assert "TCP 전체 포트 발견" not in result.stdout


def test_gui_script_compiles_without_extra_dependencies():
    py_compile.compile(str(GUI_SCRIPT), doraise=True)


def test_max_hosts_cap_enforced_without_batching(tmp_path):
    """--max-hosts 캡은 비배치 모드에서도 적용된다(이전엔 batch-size>0 일 때만 동작하던 버그)."""
    import pytest
    scanner = _load_scanner()
    args = scanner.parser().parse_args([
        "--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path),
        "--max-hosts", "2", "10.0.0.0/24",   # batch-size 기본 0 = 비배치
    ])
    with pytest.raises(ValueError):
        scanner.create_plan(args)


def test_auto_discovery_uses_ps_and_curated_nse(tmp_path):
    """발견 단계는 -PS 호스트 디스커버리(-Pn 아님), 식별 NSE 는 노이즈 제외 정체식별형."""
    scanner = _load_scanner()
    args = scanner.parser().parse_args([
        "--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "127.0.0.1",
    ])
    plan = scanner.create_plan(args)
    disc = scanner.build_command(plan, 0, "tcp_discovery")
    assert any(t.startswith("-PS") for t in disc) and "-Pn" not in disc
    ident = scanner.build_command(plan, 0, "tcp_identify", [443])
    scripts = ident[ident.index("--script") + 1]
    assert "ssh-hostkey" in scripts and "ssl-cert" in scripts
    assert "ssl-enum-ciphers" not in scripts and "ntp-monlist" not in scripts


def test_discovery_omits_open_so_udp_only_hosts_survive(tmp_path):
    """발견에 --open 이 없어야 한다: 열린 TCP 0개인 up 호스트가 XML 에서 빠지면 UDP 식별 누락."""
    scanner = _load_scanner()
    args = scanner.parser().parse_args(["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "127.0.0.1"])
    plan = scanner.create_plan(args)
    disc = scanner.build_command(plan, 0, "tcp_discovery")
    assert "--open" not in disc
    # 식별 단계엔 --open 유지(열린 포트만 깔끔히)
    assert "--open" in scanner.build_command(plan, 0, "tcp_identify", [443])


def test_discovery_uses_pe_ps_pa_probes(tmp_path):
    """발견 probe 는 -PE + -PS + -PA 조합(SYN 침묵 호스트도 ICMP/ACK 로 포착)."""
    scanner = _load_scanner()
    args = scanner.parser().parse_args(["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "127.0.0.1"])
    disc = scanner.build_command(scanner.create_plan(args), 0, "tcp_discovery")
    assert "-PE" in disc
    assert any(t.startswith("-PS") for t in disc)
    assert "-PA80,443,3389" in disc


def _udp_targets_from_log(log_path):
    """fake nmap 로그에서 udp_identify 단계의 (타깃) 토큰만 추출."""
    for entry in _read_jsonl(log_path):
        if entry["stage"] == "udp_identify":
            args = entry["args"]
            return args[args.index("-oA") + 2:]
    return None


def test_default_udp_targets_live_hosts_only(tmp_path):
    """기본값: discovery 가 찾은 live host(여기선 127.0.0.1)만 UDP 식별 대상."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    log = tmp_path / "log.jsonl"
    r = _run_scanner(["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "d",
                      "10.0.0.5", "10.0.0.6"], env={"FAKE_NMAP_LOG": str(log)})
    assert r.returncode == 0, r.stderr + r.stdout
    assert _udp_targets_from_log(log) == ["127.0.0.1"]


def test_udp_all_targets_uses_original_batch(tmp_path):
    """--udp-all-targets: discovery live host 무시하고 원본 배치 전체를 UDP 대상으로."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    log = tmp_path / "log.jsonl"
    r = _run_scanner(["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "u",
                      "--udp-all-targets", "10.0.0.5", "10.0.0.6"], env={"FAKE_NMAP_LOG": str(log)})
    assert r.returncode == 0, r.stderr + r.stdout
    # 부분 누락 방지: live host(127.0.0.1)가 아니라 원본 타깃 둘 다가 UDP 대상이어야 한다.
    assert _udp_targets_from_log(log) == ["10.0.0.5", "10.0.0.6"]


def test_live_hosts_ignores_mac_addresses(tmp_path):
    """로컬 이더넷 XML 의 MAC 주소를 타깃으로 넘기지 않는다(ipv4/ipv6 만)."""
    scanner = _load_scanner()
    xml = tmp_path / "d.tcp_discovery.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.9" addrtype="ipv4"/>'
        '<address addr="00:11:22:33:44:55" addrtype="mac"/>'
        '</host></nmaprun>',
        encoding="utf-8",
    )
    assert scanner.live_hosts_from_xml(xml) == ["10.0.0.9"]

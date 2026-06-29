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
    targets = args[args.index("-oA") + 2:]
    log = os.environ.get("FAKE_NMAP_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as fp:
            fp.write(json.dumps({"stage": stage, "args": args}, ensure_ascii=False) + "\n")
    fail_code = int(os.environ.get("FAKE_NMAP_FAIL_CODE", "7"))
    # partial: 유효한 XML 을 쓴 뒤 비정상 종료(QA-005: 부분 결과 살리기 검증용)
    if os.environ.get("FAKE_NMAP_PARTIAL_STAGE") == stage:
        write_xml(base, stage)
        return fail_code
    # corrupt: 망가진 XML 을 쓰고 rc=0 (QA-008: 손상 XML 을 '열린 포트 0' 과 구분하는지 검증용)
    if os.environ.get("FAKE_NMAP_CORRUPT_STAGE") == stage:
        base.parent.mkdir(parents=True, exist_ok=True)
        Path(str(base) + ".xml").write_text("<nmaprun><host><broken", encoding="utf-8")
        return 0
    # empty: host 없는 유효 XML, rc=0 (QA-012: 빈 결과를 정직하게 알리는지 검증용)
    if os.environ.get("FAKE_NMAP_EMPTY_STAGE") == stage:
        base.parent.mkdir(parents=True, exist_ok=True)
        Path(str(base) + ".xml").write_text('<?xml version="1.0"?><nmaprun scanner="fake"></nmaprun>', encoding="utf-8")
        return 0
    # FAIL_ALL: 모든 단계가 XML 없이 비정상 종료(QA-044: 진짜 failed/exit1 경로 검증용)
    if os.environ.get("FAKE_NMAP_FAIL_ALL"):
        return fail_code
    # FAIL_STAGE 는 콤마 구분 다중 단계 지원(QA-038: discovery 만 성공/identify 전부 실패 시나리오)
    fail_stage = os.environ.get("FAKE_NMAP_FAIL_STAGE", "")
    if stage in [s for s in fail_stage.split(",") if s]:
        return fail_code
    fail_target = os.environ.get("FAKE_NMAP_FAIL_TARGET")
    if fail_target and fail_target in targets:
        return fail_code
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
    # phase1 은 -sU 와 한 번에 돌기에 --version-all(강도 9)을 빼서 수다/증폭 UDP 의 nmap fatal 을 피한다(QA-011).
    assert "--version-all" not in flags
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
    assert Path(tcp_discovery[tcp_discovery.index("-oA") + 1]).name == "auto.127.0.0.1.tcp_discovery"
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
    # QA-041 이후 manifest 는 실제 존재하는 XML 만 광고하므로 파일을 만들어 둔다.
    for stage in ("tcp_discovery", "tcp_identify", "udp_identify"):
        (tmp_path / f"scan.{stage}.xml").write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>',
            encoding="utf-8",
        )
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
    assert (output_dir / "auto.127.0.0.1.tcp_discovery.xml").exists()
    assert (output_dir / "auto.127.0.0.1.tcp_identify.xml").exists()
    assert (output_dir / "auto.127.0.0.1.udp_identify.xml").exists()
    assert str(output_dir / "auto.127.0.0.1.tcp_discovery.xml") not in manifest["import_xml_files"]
    assert str(output_dir / "auto.127.0.0.1.tcp_identify.xml") in manifest["import_xml_files"]
    assert str(output_dir / "auto.127.0.0.1.udp_identify.xml") in manifest["import_xml_files"]
    identify_run = next(run for run in state["runs"] if run["stage_id"] == "tcp_identify")
    assert identify_run["command"][identify_run["command"].index("-p") + 1] == "T:22,443"
    zip_path = output_dir / "auto.scanops.zip"
    assert manifest["zip_path"] == str(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert {
        "auto.manifest.json",
        "auto.state.json",
        "auto.127.0.0.1.tcp_identify.xml",
        "auto.127.0.0.1.udp_identify.xml",
    } <= names


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
    assert not (output_dir / "tcp_only.127.0.0.1.udp_identify.xml").exists()


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
    assert manifest["import_xml_files"] == [str(output_dir / "udp_only.127.0.0.1.udp_identify.xml")]


def test_resume_after_failed_identification_reuses_successful_discovery(tmp_path):
    """best-effort 의미: tcp_identify 가 실패해도 udp_identify 는 계속 진행되어 부분 결과가 남는다.
    실패한 단계는 partial 로 기록되고 exit 0(쓸만한 import XML 존재). --resume 시 실패 단계만 재시도된다."""
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
    # tcp_identify 실패는 더 이상 전체 스캔을 죽이지 않는다: udp 까지 돌고 partial 로 마감(exit 0).
    assert first.returncode == 0, first.stderr + first.stdout
    failed_state = json.loads((output_dir / "resume.state.json").read_text(encoding="utf-8"))
    assert failed_state["status"] == "partial"
    # 첫 실행: discovery → (실패)identify → udp 까지 best-effort 로 진행
    assert [entry["stage"] for entry in _read_jsonl(log_path)] == [
        "tcp_discovery",
        "tcp_identify",
        "udp_identify",
    ]

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
    # resume 은 실패한 tcp_identify 만 재시도(discovery/udp 는 이미 성공 → 건너뜀).
    assert [entry["stage"] for entry in _read_jsonl(log_path)] == [
        "tcp_discovery",
        "tcp_identify",
        "udp_identify",
        "tcp_identify",
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
    assert (output_dir / "batch.127.0.0.1.b0000.tcp_identify.xml").exists()
    assert (output_dir / "batch.127.0.0.2.b0001.tcp_identify.xml").exists()
    assert manifest["import_xml_files"] == [
        str(output_dir / "batch.127.0.0.1.b0000.tcp_identify.xml"),
        str(output_dir / "batch.127.0.0.2.b0001.tcp_identify.xml"),
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


# --- 하드닝 회귀 테스트: 실패 격리 / 안정성 / 검증 ----------------------------------

def test_udp_failure_is_partial_not_fatal(tmp_path):
    """ISSUE-001/QA-002: UDP 식별 실패해도 TCP 결과로 partial 마감 + exit 0 + 재개 힌트."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "p", "127.0.0.1"],
        env={"FAKE_NMAP_FAIL_STAGE": "udp_identify"},
    )
    assert r.returncode == 0, r.stderr + r.stdout
    state = json.loads((out / "p.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "partial"
    manifest = json.loads((out / "p.manifest.json").read_text(encoding="utf-8"))
    assert str(out / "p.127.0.0.1.tcp_identify.xml") in manifest["import_xml_files"]
    assert "--resume" in r.stderr


def test_partial_xml_from_failed_stage_is_importable(tmp_path):
    """QA-005: rc≠0 이라도 host 가 든 부분 XML 은 import 목록에 포함."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "pp", "127.0.0.1"],
        env={"FAKE_NMAP_PARTIAL_STAGE": "udp_identify"},
    )
    assert r.returncode == 0, r.stderr + r.stdout
    state = json.loads((out / "pp.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "partial"
    manifest = json.loads((out / "pp.manifest.json").read_text(encoding="utf-8"))
    assert str(out / "pp.127.0.0.1.udp_identify.xml") in manifest["import_xml_files"]


def test_corrupt_discovery_xml_not_reported_as_clean_empty(tmp_path):
    """QA-008: 손상 discovery XML 은 '열린 포트 0' 이 아니라 '손상' 으로 구분되어 식별을 건너뛴다."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "c", "127.0.0.1"],
        env={"FAKE_NMAP_CORRUPT_STAGE": "tcp_discovery"},
    )
    state = json.loads((out / "c.state.json").read_text(encoding="utf-8"))
    ident = next(rn for rn in state["runs"] if rn["stage_id"] == "tcp_identify")
    assert ident.get("skipped") is True
    assert "손상" in ident.get("skip_reason", "")


def test_one_failed_batch_does_not_abort_others(tmp_path):
    """QA-003: 멀티배치에서 한 타깃의 단계 실패가 나머지 배치를 막지 않는다."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "b",
         "--batch-size", "1", "--tcp-only", "10.0.0.5", "10.0.0.6"],
        env={"FAKE_NMAP_FAIL_TARGET": "10.0.0.5"},
    )
    manifest = json.loads((out / "b.manifest.json").read_text(encoding="utf-8"))
    assert any("10.0.0.6" in p for p in manifest["import_xml_files"])
    state = json.loads((out / "b.state.json").read_text(encoding="utf-8"))
    assert state["status"] in ("partial", "done")


def test_empty_scan_reports_done_with_warning(tmp_path):
    """QA-012: 살아있는 호스트가 없으면 조용한 성공이 아니라 경고를 남긴다."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "e", "127.0.0.1"],
        env={"FAKE_NMAP_EMPTY_STAGE": "tcp_discovery"},
    )
    assert r.returncode == 0, r.stderr + r.stdout
    state = json.loads((out / "e.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "done"
    assert "가져올 결과가 없습니다" in r.stderr


def test_host_timeout_in_all_auto_commands(tmp_path):
    """QA-007: 모든 자동 단계 명령에 --host-timeout 주입(끄기는 --host-timeout 0)."""
    scanner = _load_scanner()
    args = scanner.parser().parse_args(["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "127.0.0.1"])
    plan = scanner.create_plan(args)
    for cmd in (
        scanner.build_command(plan, 0, "tcp_discovery"),
        scanner.build_command(plan, 0, "tcp_identify", [22]),
        scanner.build_command(plan, 0, "udp_identify"),
    ):
        assert "--host-timeout" in cmd and cmd[cmd.index("--host-timeout") + 1] == "15m"
    off = scanner.parser().parse_args(
        ["--dry-run", "--nmap", "nmap", "--host-timeout", "0", "--output-dir", str(tmp_path), "127.0.0.1"])
    assert "--host-timeout" not in scanner.build_command(scanner.create_plan(off), 0, "tcp_discovery")


def test_ipv6_target_rejected(tmp_path):
    """QA-016: -6 를 못 붙이는 자동 워크플로에서 IPv6 대상은 시작 전에 거절."""
    r = _run_scanner(["--nmap", "nmap", "--dry-run", "--output-dir", str(tmp_path), "fe80::1"])
    assert r.returncode == 2
    assert "IPv6" in r.stderr


def test_malformed_ports_rejected_valid_passes():
    """QA-014: 잘못된 포트 스펙 거절, 정상/열린범위는 통과."""
    import pytest
    scanner = _load_scanner()
    for bad in ("22,U:", "22,,80", "T:", "80,bad", "U:,53"):
        with pytest.raises(ValueError):
            scanner.validate_ports(bad)
    assert scanner.validate_ports("T:1-1024,U:53") == "T:1-1024,U:53"
    assert scanner.validate_ports("1-,-1024,443") == "1-,-1024,443"


def test_scan_scope_gate_cli_and_env(tmp_path):
    """QA-020: scope 밖 대상은 거절, 안쪽/CLI·ENV 양쪽 동작."""
    fake_nmap = _fake_nmap(tmp_path)
    bad = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(tmp_path / "o"), "--scan-scope", "10.0.0.0/8", "192.168.1.5"])
    assert bad.returncode == 2 and ("대역" in bad.stderr or "scope" in bad.stderr)
    ok = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(tmp_path / "o2"), "--name", "s", "--tcp-only", "10.1.2.3"],
        env={"SCANOPS_SCAN_SCOPE": "10.0.0.0/8"})
    assert ok.returncode == 0, ok.stderr + ok.stdout


def test_connect_scan_strips_udp_everywhere(tmp_path):
    """QA-010: connect(권한 불필요)는 단일 프로필에서 -sU 제거, 자동에서 UDP 단계 건너뜀."""
    scanner = _load_scanner()
    flags = scanner.build_base_flags(_args(profile="phase1", scan_type="connect"))
    assert "-sU" not in flags
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "cn", "--scan-type", "connect", "127.0.0.1"])
    assert r.returncode == 0, r.stderr + r.stdout
    state = json.loads((out / "cn.state.json").read_text(encoding="utf-8"))
    udp = next(rn for rn in state["runs"] if rn["stage_id"] == "udp_identify")
    assert udp.get("skipped") is True


def test_large_cidr_rejected_before_materialization(tmp_path):
    """QA-015: 큰 CIDR 은 전개 전에 캡으로 즉시 거절(메모리/시간 폭발 방지)."""
    import pytest
    import time as _t
    scanner = _load_scanner()
    args = scanner.parser().parse_args(["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "10.0.0.0/8"])
    start = _t.perf_counter()
    with pytest.raises(ValueError):
        scanner.create_plan(args)
    assert _t.perf_counter() - start < 2.0


def test_duplicate_targets_deduped():
    """QA-018: 중복/겹침 대상은 순서 보존하며 한 번만."""
    scanner = _load_scanner()
    hosts = scanner.expand_targets(["10.0.0.1", "10.0.0.1", "10.0.0.0/30", "10.0.0.1"], cap=100)
    assert hosts == ["10.0.0.1", "10.0.0.0", "10.0.0.2", "10.0.0.3"]


def test_range_octet_validation():
    """QA-019: base 옥텟>255·끝>255 거절, 정상 범위는 전개."""
    import pytest
    scanner = _load_scanner()
    for bad in ("10.0.999.1-5", "10.0.0.1-300"):
        with pytest.raises(ValueError):
            scanner.expand_targets([bad], cap=100)
    assert scanner.expand_targets(["10.0.0.1-3"], cap=100) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_resume_malformed_state_clean_error(tmp_path):
    """QA-017: 손상/구버전 state 는 트레이스백이 아니라 정직한 에러(rc=2)."""
    bad = tmp_path / "bad.state.json"
    bad.write_text(json.dumps({"tool": "scanops_scanner"}), encoding="utf-8")
    r = _run_scanner(["--resume", str(bad), "--nmap", "nmap", "--dry-run"])
    assert r.returncode == 2
    assert "Traceback" not in r.stderr
    assert "필수 항목" in r.stderr


def test_interrupt_writes_interrupted_state_and_resume_hint(tmp_path, monkeypatch, capsys):
    """QA-009: 정지 신호(→KeyboardInterrupt)는 status=interrupted 로 저장하고 재개 힌트를 남긴다(rc=130).
    GUI 의 CTRL_BREAK/SIGINT 정지가 도달하는 바로 그 정리 경로를 검증."""
    import signal as _sig
    scanner = _load_scanner()
    saved = {s: _sig.getsignal(getattr(_sig, s)) for s in ("SIGTERM", "SIGBREAK") if hasattr(_sig, s)}

    def boom(*_a, **_k):
        raise KeyboardInterrupt()

    try:
        args = scanner.parser().parse_args(
            ["--nmap", "nmap", "--output-dir", str(tmp_path), "--name", "i", "127.0.0.1"])
        # hermetic: 실제 nmap 설치 여부와 무관하게 create_plan 이 성공하도록 find_nmap 을 스텁한다(QA-029).
        # 어차피 subprocess.call 을 boom 으로 막아 nmap 을 실행하지 않으므로 경로 검증 외엔 영향 없음.
        monkeypatch.setattr(scanner, "find_nmap", lambda *a, **k: "nmap")
        plan = scanner.create_plan(args)
        monkeypatch.setattr(scanner.subprocess, "call", boom)
        rc = scanner.execute(plan)
        assert rc == 130
        state = json.loads((tmp_path / "i.state.json").read_text(encoding="utf-8"))
        assert state["status"] == "interrupted"
        assert "--resume" in capsys.readouterr().err
    finally:
        for s, h in saved.items():
            _sig.signal(getattr(_sig, s), h)


def test_single_workflow_resume_only_reruns_failed_batch(tmp_path):
    """QA-003 보강: --workflow single, 멀티배치에서 한 배치만 실패 → resume 은 그 배치만 재시도(성공 배치 재스캔 X)."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    log = tmp_path / "log.jsonl"
    first = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "sb", "--workflow", "single",
         "--profile", "basic", "--batch-size", "1", "10.0.0.5", "10.0.0.6", "10.0.0.7"],
        env={"FAKE_NMAP_LOG": str(log), "FAKE_NMAP_FAIL_TARGET": "10.0.0.6"},
    )
    assert first.returncode == 0, first.stderr + first.stdout  # 부분 성공(다른 배치 import 가능)
    state = json.loads((out / "sb.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "partial"
    # cursor 는 실패한 배치(10.0.0.6 = index 1)로 되감겨야 한다.
    assert state["cursor"] == 1
    first_targets = [e["args"][e["args"].index("-oA") + 2] for e in _read_jsonl(log)]
    assert first_targets == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    second = _run_scanner(
        ["--resume", str(out / "sb.state.json"), "--nmap", str(fake_nmap)],
        env={"FAKE_NMAP_LOG": str(log)},  # 실패 타깃 해제 → 이번엔 성공
    )
    assert second.returncode == 0, second.stderr + second.stdout
    resumed = json.loads((out / "sb.state.json").read_text(encoding="utf-8"))
    assert resumed["status"] == "done"
    # resume 은 실패했던 10.0.0.6 만 다시 부른다(이미 성공한 .5/.7 은 재스캔 안 함).
    all_targets = [e["args"][e["args"].index("-oA") + 2] for e in _read_jsonl(log)]
    assert all_targets == ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.6"]


def test_gui_parse_marker_handles_both_resume_line_forms():
    """QA-009 보강: GUI 표식 파서가 finalize 형/중단(interrupted) 형 재개 힌트를 모두 잡는다."""
    spec = importlib.util.spec_from_file_location("scanops_gui", GUI_SCRIPT)
    gui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gui)
    pm = gui.parse_marker
    assert pm("resume with: --resume C:/x/y.state.json")["resume"] == "C:/x/y.state.json"
    # 중단 경로의 실제 출력: 대문자 Resume + 'interrupted.' 접두사
    assert pm("interrupted. Resume with: --resume C:/x/y.state.json")["resume"] == "C:/x/y.state.json"
    assert pm("warning: 뭔가 실패")["warning"] is True
    assert pm("partial: C:/x/y.manifest.json")["partial"] is True
    assert pm("그냥 로그 한 줄")["resume"] is None


def test_single_workflow_summary_counts_live_host_with_open_port(tmp_path):
    """QA-030: 단일 워크플로(discovery 없음)도 열린 포트가 있으면 live_hosts 를 0 이 아니라 실제로 센다.
    닫힌 포트만 있는 호스트는 live 로 세지 않아 -Pn 과집계도 막는다."""
    scanner = _load_scanner()
    xml = tmp_path / "s.x.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.1.2.3" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>'
        '</host></nmaprun>',
        encoding="utf-8",
    )
    plan = {
        "runs": [{"index": 0, "batch_index": 0, "stage_id": "", "returncode": 0, "files": [str(xml)]}],
        "manifest_path": str(tmp_path / "m.json"),
        "state_path": str(tmp_path / "s.json"),
    }
    findings = scanner.scan_findings(plan)
    assert findings["live_hosts"] == 1 and findings["open_tcp"] == 1
    assert scanner.hosts_with_open_ports_from_xml(xml) == ["10.1.2.3"]

    closed = tmp_path / "c.xml"
    closed.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.1.2.4" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="closed"/></port></ports>'
        '</host></nmaprun>',
        encoding="utf-8",
    )
    assert scanner.hosts_with_open_ports_from_xml(closed) == []


def test_install_stop_handlers_registers_without_error():
    """QA-009: 정지 신호 핸들러 등록이 메인 스레드에서 예외 없이 동작."""
    import signal as _sig
    scanner = _load_scanner()
    saved = {s: _sig.getsignal(getattr(_sig, s)) for s in ("SIGTERM", "SIGBREAK") if hasattr(_sig, s)}
    try:
        scanner.install_stop_handlers()
        if hasattr(_sig, "SIGTERM"):
            assert _sig.getsignal(_sig.SIGTERM) is scanner._raise_keyboard_interrupt
    finally:
        for s, h in saved.items():
            _sig.signal(getattr(_sig, s), h)


# --- Round 3 회귀/커버리지 테스트 (QA-031..046) -------------------------------------

def test_reversed_port_range_rejected():
    """QA-035: 거꾸로 된 포트 범위(시작>끝)는 거절, 정상/열린범위는 통과."""
    import pytest
    scanner = _load_scanner()
    for bad in ("443-22", "T:1000-1", "100-50,22", "U:200-100"):
        with pytest.raises(ValueError):
            scanner.validate_ports(bad)
    assert scanner.validate_ports("22-443") == "22-443"
    assert scanner.validate_ports("1-,-1024,80") == "1-,-1024,80"


def test_all_ports_keeps_default_udp_stage(tmp_path):
    """QA-036: --all-ports 는 TCP만 담긴 --ports 가 있어도 UDP 기본 포트셋을 유지(UDP 단계 안 사라짐)."""
    scanner = _load_scanner()
    assert scanner.auto_udp_ports({"all_ports": True, "ports_override": "22,80"}).startswith("U:")
    assert scanner.auto_udp_ports({"all_ports": True, "ports_override": "T:443"}).startswith("U:")
    args = scanner.parser().parse_args(
        ["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "--all-ports", "--ports", "22,80", "127.0.0.1"])
    plan = scanner.create_plan(args)
    assert scanner.auto_udp_ports(plan).startswith("U:")


def test_tcp_only_ports_preserves_tcp_after_udp_segment():
    """QA-037: U: 뒤에 오는 T: 포트도 보존(첫 U:에서 절단하지 않음)."""
    scanner = _load_scanner()
    assert scanner.tcp_only_ports("U:53,T:80,443") == "T:80,443"
    assert scanner.tcp_only_ports("T:80,U:53,T:443") == "T:80,T:443"
    assert scanner.tcp_only_ports("T:1-65535,U:53") == "T:1-65535"


def test_open_only_does_not_add_open_to_discovery(tmp_path):
    """QA-031: --open-only 라도 discovery 엔 --open 이 붙지 않는다(UDP 전용 호스트 생존). identify 엔 붙는다."""
    scanner = _load_scanner()
    args = scanner.parser().parse_args(
        ["--dry-run", "--nmap", "nmap", "--output-dir", str(tmp_path), "--open-only", "127.0.0.1"])
    plan = scanner.create_plan(args)
    assert "--open" not in scanner.build_command(plan, 0, "tcp_discovery")
    assert "--open" in scanner.build_command(plan, 0, "tcp_identify", [443])


def test_open_only_and_include_closed_precedence():
    """QA-046: open_only 는 --open 추가, include_closed 는 제거, 둘 다면 open_only 가 이긴다. auto 도 동일(discovery 제외)."""
    scanner = _load_scanner()
    assert "--open" in scanner.build_base_flags(_args(open_only=True))
    assert "--open" not in scanner.build_base_flags(_args(profile="phase1", include_closed=True))
    assert "--open" in scanner.build_base_flags(_args(open_only=True, include_closed=True))
    assert "--open" in scanner.apply_auto_modifiers(["-sV"], {"open_only": True}, "tcp_identify")
    assert "--open" not in scanner.apply_auto_modifiers(["-sV"], {"open_only": True}, "tcp_discovery")


def test_udp_single_profile_inserts_su():
    """QA-045: --udp 는 단일 프로필에 -sU 를 (scan-type 뒤에) 삽입한다."""
    scanner = _load_scanner()
    assert "-sU" in scanner.build_base_flags(_args(udp=True))
    assert scanner.build_base_flags(_args(profile="quick", udp=True))[:2] == ["-sT", "-sU"]
    assert "-sU" not in scanner.build_base_flags(_args(udp=True, tcp_only=True))


def test_summary_counts_host_port_pairs_not_distinct_ports(tmp_path):
    """QA-039: 같은 포트번호라도 호스트가 다르면 따로 센다(노출 규모 정확)."""
    scanner = _load_scanner()
    xml = tmp_path / "two.tcp_identify.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun>'
        '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/></port>'
        '<port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
        '<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
        '</nmaprun>',
        encoding="utf-8",
    )
    plan = {"runs": [{"index": 0, "batch_index": 0, "stage_id": "tcp_identify", "returncode": 0, "files": [str(xml)]}],
            "manifest_path": str(tmp_path / "m.json"), "state_path": str(tmp_path / "s.json")}
    findings = scanner.scan_findings(plan)
    assert findings["open_tcp"] == 3
    assert findings["live_hosts"] == 2
    assert scanner.open_host_ports_from_xml(xml, "tcp") == [("10.0.0.1", 22), ("10.0.0.1", 443), ("10.0.0.2", 443)]


def test_scan_findings_counts_discovery_open_tcp_as_floor(tmp_path):
    """QA-040: identify 가 없어도 discovery 가 찾은 열린 TCP 가 open_tcp 에 반영된다."""
    scanner = _load_scanner()
    xml = tmp_path / "d.tcp_discovery.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.9" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>',
        encoding="utf-8",
    )
    plan = {"runs": [{"index": 0, "batch_index": 0, "stage_id": "tcp_discovery", "returncode": 0, "files": [str(xml)]}],
            "manifest_path": str(tmp_path / "m.json"), "state_path": str(tmp_path / "s.json")}
    findings = scanner.scan_findings(plan)
    assert findings["open_tcp"] == 1 and findings["live_hosts"] == 1


def test_discovery_only_success_is_partial_not_failed(tmp_path):
    """QA-038: discovery 만 성공(identify 전부 실패)해도 live host+open port 가 있으면 partial(exit 0),
    discovery XML 을 import fallback 으로 추천한다('모든 단계 실패' 아님)."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "do", "127.0.0.1"],
        env={"FAKE_NMAP_FAIL_STAGE": "tcp_identify,udp_identify"},
    )
    assert r.returncode == 0, r.stderr + r.stdout
    state = json.loads((out / "do.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "partial"
    assert "모든 단계 실패" not in r.stderr
    manifest = json.loads((out / "do.manifest.json").read_text(encoding="utf-8"))
    assert manifest["import_xml_files"] == [str(out / "do.127.0.0.1.tcp_discovery.xml")]
    assert "open_tcp=2" in r.stdout and "live_hosts=1" in r.stdout


def test_all_stages_failed_reports_failed_exit1(tmp_path):
    """QA-044: 모든 단계가 실패하고 import 가능한 결과가 없으면 status=failed, exit 1, '모든 단계 실패' 안내."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    r = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "fa", "127.0.0.1"],
        env={"FAKE_NMAP_FAIL_ALL": "1"},
    )
    assert r.returncode == 1, r.stderr + r.stdout
    state = json.loads((out / "fa.state.json").read_text(encoding="utf-8"))
    assert state["status"] == "failed"
    assert "모든 단계 실패" in r.stderr
    manifest = json.loads((out / "fa.manifest.json").read_text(encoding="utf-8"))
    assert manifest["import_xml_files"] == []


def test_manifest_excludes_vanished_rc0_xml(tmp_path):
    """QA-041: 성공(rc=0) 기록이라도 XML 이 사라지면 import 목록에서 빠진다."""
    scanner = _load_scanner()
    present = tmp_path / "p.tcp_identify.xml"
    present.write_text(
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>',
        encoding="utf-8",
    )
    run_present = {"stage_id": "tcp_identify", "returncode": 0, "files": [str(present)]}
    run_missing = {"stage_id": "udp_identify", "returncode": 0, "files": [str(tmp_path / "gone.udp_identify.xml")]}
    assert scanner.manifest_xml_files(run_present) == [str(present)]
    assert scanner.manifest_xml_files(run_missing) == []


def test_resume_reruns_stage_whose_output_vanished(tmp_path):
    """QA-041: 성공(rc=0) 단계의 출력이 전부 사라지면 resume 이 cursor 를 되감아 그 단계만 다시 돌리고
    XML 을 재생성한다(멀쩡한 단계는 건너뜀). 사라진 XML 을 'done' 으로 광고하지 않는다."""
    fake_nmap = _fake_nmap(tmp_path)
    out = tmp_path / "out"
    log = tmp_path / "log.jsonl"
    first = _run_scanner(
        ["--nmap", str(fake_nmap), "--output-dir", str(out), "--name", "rv", "127.0.0.1"],
        env={"FAKE_NMAP_LOG": str(log)},
    )
    assert first.returncode == 0, first.stderr + first.stdout
    gone = out / "rv.127.0.0.1.tcp_identify.xml"
    for suf in (".xml", ".nmap", ".gnmap"):
        p = out / ("rv.127.0.0.1.tcp_identify" + suf)
        if p.exists():
            p.unlink()
    second = _run_scanner(
        ["--resume", str(out / "rv.state.json"), "--nmap", str(fake_nmap)],
        env={"FAKE_NMAP_LOG": str(log)},
    )
    assert second.returncode == 0, second.stderr + second.stdout
    stages = [e["stage"] for e in _read_jsonl(log)]
    assert stages.count("tcp_identify") == 2   # 사라진 단계만 재실행
    assert stages.count("tcp_discovery") == 1  # 멀쩡한 단계는 재실행 안 함
    assert gone.exists()                        # 재생성됨
    manifest = json.loads((out / "rv.manifest.json").read_text(encoding="utf-8"))
    assert str(gone) in manifest["import_xml_files"]


def test_late_interrupt_during_finalize_keeps_terminal_status(tmp_path, monkeypatch):
    """QA-042: finalize(zip 생성 등) 중 인터럽트가 완료 상태를 'interrupted' 로 덮어쓰지 않는다."""
    scanner = _load_scanner()
    fake = _fake_nmap(tmp_path)
    args = scanner.parser().parse_args(
        ["--nmap", str(fake), "--output-dir", str(tmp_path / "o"), "--name", "li", "--zip", "127.0.0.1"])
    plan = scanner.create_plan(args)

    def boom(*_a, **_k):
        raise KeyboardInterrupt()

    monkeypatch.setattr(scanner, "create_zip", boom)
    rc = scanner.execute(plan, zip_outputs=True)
    assert rc == 0
    state = json.loads((tmp_path / "o" / "li.state.json").read_text(encoding="utf-8"))
    assert state["status"] in ("done", "partial")


def test_write_json_failure_downgrades_running_status(tmp_path, monkeypatch):
    """QA-043: 루프 도중 write_json 실패(디스크풀 등)는 status 를 'running' 으로 방치하지 않고 내려준다(exit 1)."""
    scanner = _load_scanner()
    fake = _fake_nmap(tmp_path)
    args = scanner.parser().parse_args(
        ["--nmap", str(fake), "--output-dir", str(tmp_path / "o"), "--name", "io", "--tcp-only", "127.0.0.1"])
    plan = scanner.create_plan(args)
    real = scanner.write_json
    state_flag = {"fired": False}

    def flaky(path, data):
        if data.get("runs") and not state_flag["fired"]:
            state_flag["fired"] = True
            raise OSError("disk full")
        return real(path, data)

    monkeypatch.setattr(scanner, "write_json", flaky)
    rc = scanner.execute(plan)
    assert rc == 1
    state = json.loads((tmp_path / "o" / "io.state.json").read_text(encoding="utf-8"))
    assert state["status"] != "running"


def test_final_status_text_no_false_resume_promise():
    """QA-032: rc=2(입력오류, 재개 힌트 없음)는 '재개 가능' 을 안내하지 않는다(순수 함수, headless)."""
    spec = importlib.util.spec_from_file_location("scanops_gui_fs", GUI_SCRIPT)
    gui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gui)
    fst = gui.final_status_text
    assert "재개 불가" in fst(2, False, 0, False)
    assert fst(130, False, 0, False).startswith("중지됨")
    assert "재개 실행" in fst(1, False, 0, True)
    assert "재개할 상태가 없습니다" in fst(1, False, 0, False)
    assert fst(0, True, 2, False).startswith("부분 완료")
    assert fst(0, False, 0, False) == "완료"

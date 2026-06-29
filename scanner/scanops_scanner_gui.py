#!/usr/bin/env python3
"""Tkinter GUI for the standalone ScanOps scanner."""
from __future__ import annotations

import os
import queue
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

# tkinter 를 최상단에서 강제로 import 하면 headless/ Tk 없는 파이썬에서 모듈 자체가 import 불가가 되어
# 순수 함수(parse_marker, GUI↔CLI 표식 계약)와 상수까지 단위 테스트할 수 없다(QA-028).
# GUI 를 '실행' 하려면 당연히 tkinter 가 필요하지만, 'import' 하는 데는 필요 없게 가드한다.
try:
    from tkinter import BooleanVar, StringVar, Tk, filedialog, messagebox
    from tkinter import scrolledtext, ttk
    _TK_IMPORT_ERROR: Exception | None = None
except ImportError as _exc:  # noqa: F841 — headless 환경: 순수 로직만 import 가능하게 유지
    BooleanVar = StringVar = Tk = filedialog = messagebox = None  # type: ignore[assignment]
    scrolledtext = ttk = None  # type: ignore[assignment]
    _TK_IMPORT_ERROR = _exc

SCRIPT = Path(__file__).with_name("scanops_scanner.py")
DEFAULT_OUTPUT = "scanops_scans"


def parse_marker(line: str) -> dict:
    """CLI 출력 한 줄에서 표식 추출(순수 함수, Tk 불필요 → 단위 테스트 가능).
    재개 힌트는 finalize 의 'resume with: --resume PATH' 와 중단의
    'interrupted. Resume with: --resume PATH' 두 형태 모두 대소문자/접두사 무관 부분일치로 잡는다."""
    stripped = line.strip()
    low = stripped.lower()
    marker = "resume with: --resume "
    idx = low.find(marker)
    return {
        "resume": stripped[idx + len(marker):].strip() if idx >= 0 else None,
        "warning": low.startswith("warning:"),
        "partial": low.startswith("partial:"),
    }

RUN_MODE_LABELS = {
    "auto": "자동 스캔 - 열린 포트와 용도 파악",
    "single_basic": "단일 실행 - 빠른 서비스 확인",
    "single_precision": "단일 실행 - 전체 포트 정밀 확인",
    "single_quick": "단일 실행 - 주요 TCP 포트",
    "single_light": "단일 실행 - 최소 TCP 포트",
}
RUN_MODE_BY_LABEL = {v: k for k, v in RUN_MODE_LABELS.items()}
RUN_MODE_TO_PROFILE = {
    "single_basic": "basic",
    "single_precision": "phase1",
    "single_quick": "quick",
    "single_light": "light",
}
RUN_MODE_DESCRIPTIONS = {
    "auto": "한 번 실행하면 열린 TCP 발견, 발견된 TCP 식별, 주요 UDP 확인을 내부적으로 이어서 실행합니다.",
    "single_basic": "대상이 살아있다고 보고 서비스/버전 확인만 한 번 실행합니다. 빠른 재확인용입니다.",
    "single_precision": "전체 TCP와 주요 UDP 확인을 한 번에 실행합니다. 자동 스캔보다 중복 작업이 많을 수 있습니다.",
    "single_quick": "상위 1000 TCP 포트에서 서비스와 버전을 확인합니다.",
    "single_light": "상위 100 TCP 포트만 빠르게 확인합니다.",
}
PORT_PRESETS = {
    "프로필 기본": "",
    "웹/원격": "22,80,443,3389,8080,8443",
    "웹 서비스": "80,443,8000,8080,8443,9000,9443",
    "원격 접속": "22,23,3389,5900",
    "DB": "1433,1521,3306,5432,6379,9200,27017",
    "직접 입력": "",
}
SCAN_TYPES = {
    "프로필 기본": "",
    "권한 불필요 - TCP Connect": "connect",
    "관리자 권한 - TCP SYN": "syn",
}


class ScannerGui:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("ScanOps Scanner")
        self.root.minsize(940, 720)

        self.proc: subprocess.Popen | None = None
        self.output_queue: queue.Queue[tuple[str, str | int]] = queue.Queue()

        self.target_file = StringVar()
        self.output_dir = StringVar(value=DEFAULT_OUTPUT)
        self.output_name = StringVar()
        self.nmap_path = StringVar()
        self.mode_label = StringVar(value=RUN_MODE_LABELS["auto"])
        self.mode_desc = StringVar(value=RUN_MODE_DESCRIPTIONS["auto"])
        self.port_preset = StringVar(value="프로필 기본")
        self.ports = StringVar()
        self.scan_type_label = StringVar(value="프로필 기본")
        self.tcp_only = BooleanVar(value=False)
        self.udp = BooleanVar(value=False)
        self.udp_all_targets = BooleanVar(value=False)
        self.nse_default = BooleanVar(value=False)
        self.no_scripts = BooleanVar(value=False)
        self.open_only = BooleanVar(value=False)
        self.include_closed = BooleanVar(value=False)
        self.batch_size = StringVar(value="0")
        self.zip_outputs = BooleanVar(value=True)
        self.resume_path = StringVar()
        self.status = StringVar(value="준비됨")
        self.show_advanced = BooleanVar(value=False)
        self.show_nse = BooleanVar(value=False)
        # 실행 중 CLI 출력에서 추출하는 표식: 재개 state 경로 / 경고 수 / partial 여부.
        self._resume_hint = ""
        self._warn_count = 0
        self._partial = False

        self._build_ui()
        self.root.after(120, self._drain_output)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(7, weight=1)

        target = ttk.LabelFrame(outer, text="대상")
        target.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        target.columnconfigure(0, weight=1)
        self.targets_text = scrolledtext.ScrolledText(target, height=5, wrap="word")
        self.targets_text.grid(row=0, column=0, columnspan=4, sticky="ew", padx=10, pady=(8, 6))
        ttk.Label(target, text="IP/CIDR/범위를 줄바꿈, 쉼표, 공백으로 입력").grid(row=1, column=0, sticky="w", padx=10, pady=(0, 8))
        ttk.Entry(target, textvariable=self.target_file).grid(row=2, column=0, sticky="ew", padx=(10, 6), pady=(0, 10))
        ttk.Button(target, text="대상 파일", command=self._browse_target_file).grid(row=2, column=1, padx=4, pady=(0, 10))
        ttk.Button(target, text="비우기", command=lambda: self.targets_text.delete("1.0", "end")).grid(row=2, column=2, padx=4, pady=(0, 10))

        basics = ttk.LabelFrame(outer, text="스캔 실행 방식")
        basics.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        basics.columnconfigure(1, weight=1)
        basics.columnconfigure(3, weight=1)
        ttk.Label(basics, text="실행 방식").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        mode = ttk.Combobox(basics, textvariable=self.mode_label, values=list(RUN_MODE_BY_LABEL), state="readonly")
        mode.grid(row=0, column=1, sticky="ew", padx=6, pady=8)
        mode.bind("<<ComboboxSelected>>", self._mode_changed)
        ttk.Label(basics, textvariable=self.mode_desc, wraplength=520).grid(row=0, column=2, columnspan=2, sticky="w", padx=10, pady=8)
        ttk.Label(basics, text="결과 폴더").grid(row=1, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(basics, textvariable=self.output_dir).grid(row=1, column=1, sticky="ew", padx=6, pady=8)
        ttk.Button(basics, text="찾기", command=self._browse_output_dir).grid(row=1, column=2, padx=6, pady=8)
        ttk.Button(basics, text="열기", command=self._open_output_dir).grid(row=1, column=3, sticky="w", padx=(0, 10), pady=8)
        ttk.Label(basics, text="결과 이름").grid(row=2, column=0, sticky="w", padx=10, pady=(0, 10))
        ttk.Entry(basics, textvariable=self.output_name).grid(row=2, column=1, sticky="ew", padx=6, pady=(0, 10))
        ttk.Label(basics, text="비우면 scan_날짜").grid(row=2, column=2, columnspan=2, sticky="w", padx=6, pady=(0, 10))

        expected = ttk.LabelFrame(outer, text="스캔이 끝나면 얻는 정보")
        expected.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        expected.columnconfigure(0, weight=1)
        self.expected_text = StringVar()
        ttk.Label(expected, textvariable=self.expected_text, wraplength=850).grid(row=0, column=0, sticky="w", padx=10, pady=8)

        toggles = ttk.Frame(outer)
        toggles.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(toggles, text="상세 옵션", command=self._toggle_advanced).pack(side="left", padx=(0, 8))
        ttk.Button(toggles, text="NSE", command=self._toggle_nse).pack(side="left", padx=(0, 8))
        ttk.Button(toggles, text="자동 스캔 기본값", command=self._apply_auto).pack(side="left")

        self.advanced = ttk.LabelFrame(outer, text="상세 옵션")
        self.advanced.columnconfigure(1, weight=1)
        self.advanced.columnconfigure(3, weight=1)
        ttk.Label(self.advanced, text="포트 묶음").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        port_combo = ttk.Combobox(self.advanced, textvariable=self.port_preset, values=list(PORT_PRESETS), state="readonly")
        port_combo.grid(row=0, column=1, sticky="ew", padx=6, pady=8)
        port_combo.bind("<<ComboboxSelected>>", self._apply_port_preset)
        ttk.Label(self.advanced, text="포트").grid(row=0, column=2, sticky="w", padx=10, pady=8)
        ttk.Entry(self.advanced, textvariable=self.ports).grid(row=0, column=3, sticky="ew", padx=(6, 10), pady=8)
        ttk.Label(self.advanced, text="스캔 방식").grid(row=1, column=0, sticky="w", padx=10, pady=8)
        ttk.Combobox(self.advanced, textvariable=self.scan_type_label, values=list(SCAN_TYPES), state="readonly").grid(
            row=1, column=1, sticky="ew", padx=6, pady=8
        )
        ttk.Label(self.advanced, text="배치 크기").grid(row=1, column=2, sticky="w", padx=10, pady=8)
        ttk.Entry(self.advanced, textvariable=self.batch_size).grid(row=1, column=3, sticky="ew", padx=(6, 10), pady=8)
        checks = ttk.Frame(self.advanced)
        checks.grid(row=2, column=0, columnspan=4, sticky="ew", padx=10, pady=(2, 8))
        ttk.Checkbutton(checks, text="TCP만", variable=self.tcp_only).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="단일 실행에 UDP 추가", variable=self.udp).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="숨은 UDP 전용 호스트도 확인", variable=self.udp_all_targets).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="열린 포트만", variable=self.open_only).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="닫힌 포트 포함", variable=self.include_closed).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="zip 생성", variable=self.zip_outputs).pack(side="left")
        ttk.Label(self.advanced, text="nmap 경로").grid(row=3, column=0, sticky="w", padx=10, pady=(0, 10))
        ttk.Entry(self.advanced, textvariable=self.nmap_path).grid(row=3, column=1, columnspan=2, sticky="ew", padx=6, pady=(0, 10))
        ttk.Button(self.advanced, text="찾기", command=self._browse_nmap).grid(row=3, column=3, sticky="w", padx=(6, 10), pady=(0, 10))

        self.nse = ttk.LabelFrame(outer, text="NSE")
        self.nse.columnconfigure(1, weight=1)
        ttk.Checkbutton(self.nse, text="단일 실행에서 기본 NSE 추가", variable=self.nse_default).grid(row=0, column=0, sticky="w", padx=10, pady=8)
        ttk.Checkbutton(self.nse, text="NSE 끄기", variable=self.no_scripts).grid(row=0, column=1, sticky="w", padx=10, pady=8)
        ttk.Label(self.nse, text="자동 스캔은 용도 파악에 필요한 기본 NSE를 포함합니다. 결과가 너무 많으면 여기서 끌 수 있습니다.").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 10)
        )

        resume = ttk.LabelFrame(outer, text="중단된 스캔 재개")
        resume.grid(row=6, column=0, sticky="ew", pady=(0, 10))
        resume.columnconfigure(0, weight=1)
        ttk.Entry(resume, textvariable=self.resume_path).grid(row=0, column=0, sticky="ew", padx=(10, 6), pady=8)
        ttk.Button(resume, text="state.json 선택", command=self._browse_resume).grid(row=0, column=1, padx=6, pady=8)
        ttk.Button(resume, text="재개 실행", command=lambda: self._start(dry_run=False, resume=True)).grid(row=0, column=2, padx=(6, 10), pady=8)

        log_frame = ttk.LabelFrame(outer, text="명령/실행 로그")
        log_frame.grid(row=7, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = scrolledtext.ScrolledText(log_frame, height=13, wrap="word")
        self.log.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        actions = ttk.Frame(outer)
        actions.grid(row=8, column=0, sticky="ew", pady=(10, 0))
        self.preview_btn = ttk.Button(actions, text="명령 확인", command=lambda: self._start(dry_run=True))
        self.preview_btn.pack(side="left", padx=(0, 8))
        self.start_btn = ttk.Button(actions, text="스캔 시작", command=lambda: self._start(dry_run=False))
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = ttk.Button(actions, text="중지", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="로그 비우기", command=lambda: self.log.delete("1.0", "end")).pack(side="left", padx=(0, 12))
        ttk.Label(actions, textvariable=self.status).pack(side="left")
        self._mode_changed()

    def _mode_changed(self, _event=None) -> None:
        mode = self._mode()
        self.mode_desc.set(RUN_MODE_DESCRIPTIONS.get(mode, ""))
        if mode == "auto":
            self.expected_text.set(
                "내부적으로 전체 TCP에서 현재 열린 포트를 먼저 찾고, 발견된 TCP 포트만 다시 확인해 서비스명/제품/버전/NSE 단서를 붙인 뒤, 주요 UDP 서비스도 확인합니다. 결과 XML에는 현재 열린 포트, 포트 용도 추정 단서, 웹 제목/서버 헤더/TLS 인증서/SSH 키/NetBIOS/RDP/NTP/RPC 같은 관리자 설명용 정보가 남습니다."
            )
        elif mode == "single_basic":
            self.expected_text.set("기본 서비스/버전 확인(-Pn -sV -T4)을 한 번 실행합니다. 빠른 재확인에는 좋지만 전체 TCP 발견이나 UDP 용도 단서는 제한적입니다.")
        elif mode == "single_precision":
            self.expected_text.set("전체 TCP 포트와 주요 UDP 포트를 한 번에 확인하고 기본 NSE를 실행합니다. 자동 스캔처럼 열린 TCP만 좁혀서 2차 식별하지는 않습니다.")
        elif mode == "single_quick":
            self.expected_text.set("흔한 TCP 포트 위주로 열린 서비스를 빠르게 확인합니다. 전체 포트 누락 가능성은 있습니다.")
        else:
            self.expected_text.set("가장 흔한 TCP 포트만 확인합니다. 대상이 많은 경우 사전 점검용입니다.")
        if mode in {"auto", "single_precision"}:
            self.port_preset.set("프로필 기본")
            self.ports.set("")

    def _apply_auto(self) -> None:
        self.mode_label.set(RUN_MODE_LABELS["auto"])
        self._mode_changed()

    def _toggle_advanced(self) -> None:
        self.show_advanced.set(not self.show_advanced.get())
        if self.show_advanced.get():
            self.advanced.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        else:
            self.advanced.grid_remove()

    def _toggle_nse(self) -> None:
        self.show_nse.set(not self.show_nse.get())
        if self.show_nse.get():
            self.nse.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        else:
            self.nse.grid_remove()

    def _apply_port_preset(self, _event=None) -> None:
        value = PORT_PRESETS.get(self.port_preset.get(), "")
        self.ports.set(value)

    def _mode(self) -> str:
        return RUN_MODE_BY_LABEL.get(self.mode_label.get(), "auto")

    def _single_profile(self) -> str:
        return RUN_MODE_TO_PROFILE.get(self._mode(), "basic")

    def _browse_target_file(self) -> None:
        path = filedialog.askopenfilename(title="대상 파일 선택", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.target_file.set(path)

    def _browse_output_dir(self) -> None:
        path = filedialog.askdirectory(title="결과 폴더 선택")
        if path:
            self.output_dir.set(path)

    def _browse_nmap(self) -> None:
        path = filedialog.askopenfilename(title="nmap 실행 파일 선택", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.nmap_path.set(path)

    def _browse_resume(self) -> None:
        path = filedialog.askopenfilename(title="state.json 선택", filetypes=[("State files", "*.json"), ("All files", "*.*")])
        if path:
            self.resume_path.set(path)

    def _targets(self) -> list[str]:
        tokens: list[str] = []
        for line in self.targets_text.get("1.0", "end").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                tokens.extend(t for t in re.split(r"[\s,]+", line) if t)
        return tokens

    def _base_command(self) -> list[str]:
        if not SCRIPT.exists():
            raise ValueError(f"scanops_scanner.py 를 찾을 수 없습니다: {SCRIPT}")
        return [sys.executable, "-u", str(SCRIPT)]

    def _command(self, *, dry_run: bool, resume: bool = False) -> list[str]:
        cmd = self._base_command()
        nmap = self.nmap_path.get().strip()
        if resume:
            state = self.resume_path.get().strip()
            if not state:
                raise ValueError("재개하려면 *.state.json 파일을 선택하세요.")
            cmd += ["--resume", state]
            if nmap:
                cmd += ["--nmap", nmap]
            if self.zip_outputs.get():
                cmd.append("--zip")
            if dry_run:
                cmd.append("--dry-run")
            return cmd

        targets = self._targets()
        target_file = self.target_file.get().strip()
        if not targets and not target_file:
            raise ValueError("대상 IP 또는 대상 파일을 입력하세요.")
        cmd += ["--output-dir", self.output_dir.get().strip() or DEFAULT_OUTPUT]
        if self.output_name.get().strip():
            cmd += ["--name", self.output_name.get().strip()]
        if nmap:
            cmd += ["--nmap", nmap]
        mode = self._mode()
        if mode == "auto":
            cmd += ["--workflow", "auto"]
        else:
            cmd += ["--workflow", "single", "--profile", self._single_profile()]
        ports = self.ports.get().strip()
        if ports:
            cmd += ["--ports", ports]
        scan_type = SCAN_TYPES.get(self.scan_type_label.get(), "")
        if scan_type:
            cmd += ["--scan-type", scan_type]
        if self.tcp_only.get():
            cmd.append("--tcp-only")
        if self.udp.get():
            cmd.append("--udp")
        if self.udp_all_targets.get() and mode == "auto":
            cmd.append("--udp-all-targets")
        if self.nse_default.get():
            cmd.append("--nse-default")
        if self.no_scripts.get():
            cmd.append("--no-scripts")
        if self.open_only.get():
            cmd.append("--open-only")
        if self.include_closed.get():
            cmd.append("--include-closed")
        batch = self.batch_size.get().strip()
        if batch and batch != "0":
            if not batch.isdigit():
                raise ValueError("배치 크기는 숫자여야 합니다.")
            cmd += ["--batch-size", batch]
        if target_file:
            cmd += ["--targets-file", target_file]
        if self.zip_outputs.get():
            cmd.append("--zip")
        if dry_run:
            cmd.append("--dry-run")
        cmd += targets
        return cmd

    def _start(self, *, dry_run: bool, resume: bool = False) -> None:
        if self.proc is not None:
            messagebox.showwarning("실행 중", "이미 스캔이 실행 중입니다.")
            return
        try:
            cmd = self._command(dry_run=dry_run, resume=resume)
        except ValueError as exc:
            messagebox.showerror("입력 확인", str(exc))
            return
        self._append_log("\n$ " + self._display_command(cmd) + "\n")
        self._resume_hint = ""
        self._warn_count = 0
        self._partial = False
        self._set_running(True)
        self.status.set("명령 확인 중" if dry_run else "스캔 실행 중")
        threading.Thread(target=self._run_process, args=(cmd,), daemon=True).start()

    def _run_process(self, cmd: list[str]) -> None:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "bufsize": 1,
            "env": env,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            kwargs["start_new_session"] = True
        try:
            self.proc = subprocess.Popen(cmd, **kwargs)
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self.output_queue.put(("line", line))
            self.output_queue.put(("done", self.proc.wait()))
        except OSError as exc:
            self.output_queue.put(("line", f"error: {exc}\n"))
            self.output_queue.put(("done", 1))

    def _stop(self) -> None:
        if self.proc is None:
            return
        self._append_log("\n중지 요청(정상 종료 시도)...\n")
        proc = self.proc
        # 먼저 정상 종료 신호를 보내 CLI 의 interrupted 정리(상태 저장 + 재개 힌트)가 돌게 한다.
        # Windows: CTRL_BREAK_EVENT(프로세스 그룹), POSIX: 그룹에 SIGINT. CLI 가 KeyboardInterrupt 로 처리.
        try:
            if os.name == "nt":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except (OSError, ValueError):
            try:
                proc.terminate()
            except OSError:
                pass
        # 정상 종료가 지연되면 강제 종료로 폴백(좀비 방지).
        self.root.after(6000, lambda: self._force_kill(proc))

    def _force_kill(self, proc: subprocess.Popen) -> None:
        if self.proc is not proc or proc.poll() is not None:
            return  # 이미 종료됨
        self._append_log("정상 종료 지연 — 강제 종료합니다.\n")
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass

    def _drain_output(self) -> None:
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "line":
                    line = str(payload)
                    self._scan_markers(line)
                    self._append_log(line)
                elif kind == "done":
                    rc = int(payload)
                    self.proc = None
                    self._set_running(False)
                    self.status.set(self._final_status(rc))
                    # 실패/부분/중단 시 재개 경로를 자동 채워 사용자가 바로 [재개 실행] 할 수 있게.
                    if self._resume_hint and not self.resume_path.get().strip():
                        self.resume_path.set(self._resume_hint)
                    self._append_log(f"\nexit code: {rc}\n")
        except queue.Empty:
            pass
        self.root.after(120, self._drain_output)

    def _scan_markers(self, line: str) -> None:
        m = parse_marker(line)
        if m["resume"]:
            self._resume_hint = m["resume"]
        if m["warning"]:
            self._warn_count += 1
        if m["partial"]:
            self._partial = True

    def _final_status(self, rc: int) -> str:
        if rc == 0:
            if self._partial:
                return f"부분 완료 — 경고 {self._warn_count}건(로그 확인)"
            if self._warn_count:
                return f"완료(경고 {self._warn_count}건 — 로그 확인)"
            return "완료"
        if rc == 130:
            return "중지됨 — [재개 실행]으로 이어할 수 있습니다"
        return f"실패(종료 코드 {rc}) — [재개 실행] 가능"

    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.preview_btn.configure(state=state)
        self.start_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _append_log(self, text: str) -> None:
        self.log.insert("end", text)
        self.log.see("end")

    def _open_output_dir(self) -> None:
        path = Path(self.output_dir.get().strip() or DEFAULT_OUTPUT)
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])

    @staticmethod
    def _display_command(cmd: list[str]) -> str:
        try:
            import shlex
            return shlex.join(cmd)
        except Exception:
            return " ".join(cmd)

    def _close(self) -> None:
        if self.proc is not None and not messagebox.askyesno("종료", "스캔이 실행 중입니다. 중지하고 닫을까요?"):
            return
        proc = self.proc
        if proc is not None:
            # 정상 종료 신호를 보낸 뒤, 창을 닫기 전에 잠깐 기다렸다가 안 죽으면 강제 종료한다.
            # (창을 바로 destroy 하면 _stop 의 after(force_kill) 타이머가 사라져 nmap 이 고아가 될 수 있음.)
            self._stop()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self._force_kill(proc)
            except OSError:
                pass
        self.root.destroy()


def main() -> None:
    if _TK_IMPORT_ERROR is not None:
        raise SystemExit(
            "이 GUI 는 tkinter 가 필요합니다. tkinter 를 설치/활성화한 파이썬으로 실행하세요.\n"
            f"(tkinter import 실패: {_TK_IMPORT_ERROR})"
        )
    root = Tk()
    try:
        root.option_add("*Font", ("Malgun Gothic", 10))
    except Exception:
        pass
    ScannerGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()

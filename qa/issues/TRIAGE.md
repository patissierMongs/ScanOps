# QA triage — standalone scanner

Source: 6-dimension multi-agent analysis + adversarial verification. 40 raw -> 32 confirmed.
Full evidence: qa/analysis_result.json. ISSUE-001 (the originally reported UDP exit1) is QA-002's sibling root cause.

| ID | grp | sev | disp | title |
|----|-----|-----|------|-------|
| QA-002 | A | high | FIX | tcp_identify rc!=0 aborts the whole plan, discarding successful tcp_discovery AND skipping |
| QA-003 | A | high | FIX | One bad host/stage in a single batch aborts ALL remaining batches in a multi-batch run |
| QA-004 | A | medium | FIX | tcp_discovery rc!=0 aborts before any identify even when discovery wrote a usable host/por |
| QA-005 | A | medium | FIX | Partial-but-valid XML from a non-zero-exit stage is written to disk but silently excluded  |
| QA-006 | A | medium | FIX | fail_plan writes manifest with returncode==0 filter, so a mid-plan failure yields a manife |
| QA-007 | B | high | FIX | No nmap --host-timeout and no subprocess timeout: a single host can hang the whole scan fo |
| QA-008 | C | high | FIX | Corrupt/truncated discovery XML is swallowed, yielding an empty-but-"done" scan with exit  |
| QA-009 | D | high | FIX | GUI stop (taskkill /F /T) force-kills the scanner, so state.json is left permanently as st |
| QA-010 | E | high | FIX | --scan-type connect still emits -sU in auto UDP stage, so the 'no privileges' choice fatal |
| QA-011 | F | high | FIX | phase1 'precision' single-run preset reintroduces the fatal -sU + --version-all combo the  |
| QA-012 | G | high | FIX | "No live hosts" / "no open ports" is reported as a clean rc=0 skip, not honestly surfaced  |
| QA-013 | H | medium | FIX | protocol_ports misclassifies a bare port that follows a U: token as UDP, silently dropping |
| QA-014 | H | medium | FIX | validate_ports accepts malformed specs (lone 'T:'/'U:', empty/double commas) that flow str |
| QA-015 | I | high | FIX | CIDR/range cap is checked AFTER full materialization, so a large network (IPv4 /8 or any I |
| QA-016 | I | medium | FIX | IPv6 targets are accepted and expanded but the scan never gets -6, so nmap aborts (and in  |
| QA-017 | I | medium | FIX | Non-ValueError/OSError exceptions (KeyError from malformed state file on --resume) escape  |
| QA-018 | I | low | FIX | Duplicate / overlapping targets are never deduplicated, causing redundant scans and output |
| QA-019 | I | low | FIX | IP range/CIDR validation gaps: base octets >255 accepted, invalid CIDR silently passed thr |
| QA-020 | I | high | FIX | Standalone scanner enforces no SCANOPS_SCAN_SCOPE allowlist — a copy-and-run footgun that  |
| QA-021 | E | medium | FIX | Default auto workflow silently drops UDP-only hosts; GUI gives no way to enable full UDP c |
| QA-022 | G | medium | FIX | Resume UX: the only resume hint goes to stderr from the CLI; the GUI gives no resume affor |
| QA-023 | I | low | FIX | No guard against resuming/running a state that is still status=running — two scanners can  |
| QA-024 | Z | low | DEFER | Auto discovery stage keeps raw-socket-only probes (-PE/-PA/--defeat-rst-ratelimit) even un |
| QA-025 | Z | low | DEFER | GUI 'TCP만'/'단일 실행에 UDP 추가'/NSE toggles silently no-op or conflict depending on mode, with  |
| QA-026 | Z | low | DEFER | GUI never validates output name / batch-size numeric edge cases or surfaces CLI validation |
| QA-027 | D | low | FIX | GUI surfaces non-zero CLI exit purely as a numeric code with no indication that partial re |

## Fix groups

- **A** failure isolation: stages best-effort, partial status, manifest includes parseable XML, exit 0 when usable data exists (fixes ISSUE-001 + QA-002..006)
- **B** hang guard: nmap --host-timeout on all auto stages (QA-007)
- **C** parse-error vs empty: corrupt discovery XML no longer silently reported as zero exposure (QA-008)
- **D** GUI graceful stop: CTRL_BREAK/SIGINT -> interrupted state + resume autofill + partial display (QA-009, QA-027)
- **E** connect/UDP coverage: connect scan skips UDP cleanly; GUI udp-all-targets toggle (QA-010, QA-021)
- **F** phase1 preset: drop fatal -sU+--version-all (QA-011)
- **G** honesty/summary: end-of-scan summary + empty/partial warnings + resume hint (QA-012, QA-022)
- **H** port-spec validation: protocol_ports + validate_ports tightening (QA-013, QA-014)
- **I** input/robustness: CIDR cap pre-check, IPv6 reject, dedup, range octets, malformed-state guard, scope allowlist, running-state guard (QA-015..020, QA-023)
- **Z** deferred (cosmetic/low value, recorded only): QA-024, QA-025, QA-026, QA-028

## Round 2 (loop: standalone re-analysis, fake-nmap harness)

Source: live baseline run in headless container (40 pass / 2 fail) + standalone re-analysis. New issues not covered by QA-002..027.

| ID | grp | sev | disp | title |
|----|-----|-----|------|-------|
| QA-028 | R2 | medium | FIX | GUI couples pure CLI-output logic (parse_marker) to a top-level tkinter import → untestable headless |
| QA-029 | R2 | low | FIX | Interrupt/resume test is non-hermetic (needs real nmap), suite pass/fail varies by machine |
| QA-030 | R2 | medium | FIX | Single-workflow summary always reports live_hosts=0 even with hosts up + open ports |

## Round 3 (loop: 5-dimension multi-agent analysis + adversarial verify)

Source: scanner-qa-discovery workflow (5 analyzers × adversarial troubleshooter). 19 candidates → 16 confirmed new/real (3 rejected: --host-timeout 0 backstop [covered by QA-007 + documented opt-out], single-workflow host-timeout test [code correct], resume-of-done idempotency test [code correct]).

| ID | grp | sev | disp | title |
|----|-----|-----|------|-------|
| QA-031 | R3 | high | FIX | open_only injects --open into auto tcp_discovery, breaking UDP-only-host survival invariant |
| QA-032 | R3 | medium | FIX | GUI _final_status promises resume for rc=2 validation errors where no state.json exists |
| QA-033 | R3 | medium | FIX | Resume-path autofill never refreshes → second failed scan resumes the FIRST scan's state |
| QA-034 | R3 | low | FIX | Resume button never disabled while a scan is running (_set_running omits it) |
| QA-035 | R3 | medium | FIX | validate_ports accepts reversed port ranges (443-22) → fatal nmap error / empty failed scan |
| QA-036 | R3 | medium | FIX | --all-ports + a TCP-only --ports silently disables the UDP identify stage |
| QA-037 | R3 | low | FIX | tcp_only_ports truncates spec at first 'U:', dropping later T: ports (latent, preset-masked) |
| QA-038 | R3 | high | FIX | discovery-only-success mislabeled 'failed' (exit 1) despite live hosts + open ports |
| QA-039 | R3 | medium | FIX | summary open_tcp/open_udp count distinct port numbers, under-reporting multi-host exposure |
| QA-040 | R3 | medium | FIX | scan_findings never counts discovery open TCP → open_tcp=0 when identify skipped/fails |
| QA-041 | R3 | high | FIX | resume trusts recorded files w/o existence check → manifest advertises vanished XML as done |
| QA-042 | R3 | medium | FIX | interrupt during finalize overwrites completed done/partial status with 'interrupted' |
| QA-043 | R3 | medium | FIX | write_json non-atomic + execute() only catches KeyboardInterrupt → status='running' stranded |
| QA-044 | R3 | high | FIX(test) | finalize_plan 'failed'/exit-1 path (all stages fail) is completely untested |
| QA-045 | R3 | low | FILE-ONLY | --udp single-profile -sU insertion has no test (no code defect; low-value coverage) |
| QA-046 | R3 | medium | FIX(test) | --open-only add / --open-only vs --include-closed precedence untested |
# ScanOps Progress Record

[한국어](PROGRESS.md) | **English**

The implementation status below was verified by reading the code as of 2026-09-27, not by trusting documents or commit messages. A passing test suite was not treated as proof of completeness.

## Final goal

Store nmap results in a database as individual findings, and make the following work end to end for every finding:

1. Findings are created from scans
2. Service category, risk level and KISA (Korea Internet & Security Agency) / NIS (National Intelligence Service) references are attached automatically
3. Owners and deadlines are assigned
4. Remediation is confirmed by rescanning
5. Evidence is exported in an audit report

On top of that, the tool must install offline on an air-gapped Windows server and be used by the team through a Korean browser UI (`docs/DESIGN.md`, section 8).

## Current implementation status

| Feature | Status | Code location checked |
|---|---|---|
| Login and token auth, initial admin password and forced change | Implemented | `backend/scanops/api/auth.py`, `backend/scanops/seed/bootstrap.py` |
| Three roles (admin/auditor/viewer) and user management | Implemented | `backend/scanops/api/deps.py` `require_role`, `backend/scanops/api/users.py` |
| nmap XML (Extensible Markup Language) import | Implemented | `backend/scanops/api/scans.py` `POST /import`, `backend/scanops/scanning/nmap_parse.py` |
| Folder import (staged scan folders, standalone scanner manifests) | Implemented | `backend/scanops/api/scans.py` `POST /import-bundle` |
| Run scans from the web (staged scan engine) | Implemented | `backend/scanops/api/scans.py` `POST /run-staged`, `engine/scanops_engine/pipeline.py` |
| One-shot run and raw command run | Implemented | `backend/scanops/api/scans.py` `POST /run`, `POST /run-command` |
| Stop, resume and rescan hosts in the retry queue | Implemented | `backend/scanops/api/scans.py` `/{scan_id}/stop`, `/resume`, `/retry-timeouts` |
| Allowed scan scope (`SCANOPS_SCAN_SCOPE`) | Implemented | `backend/scanops/scanning/scope.py` `check_scope` |
| 105-service taxonomy, risk levels, KISA/NIS references | Implemented | `backend/scanops/seed/categories.json`, `backend/scanops/scanning/taxonomy.py` |
| End-of-life (EOL) product detection | Implemented | `backend/scanops/seed/eol_products.json`, `backend/scanops/scanning/taxonomy.py` |
| Raw-response signature matching for `unknown` ports | Implemented | `backend/scanops/scanning/fingerprints.py`, `backend/scanops/seed/fingerprint_signatures.json` |
| Organization risk rules (service, product, CPE (Common Platform Enumeration)) | Implemented | `backend/scanops/api/rules.py` |
| Finding status, deadline, assignee and change history | Implemented | `backend/scanops/api/findings.py` `PATCH /{fid}`, `GET /{fid}/events` |
| Closure on rescan (unobserved ports closed automatically) | Implemented | `backend/scanops/scanning/ingest.py` `ingest`, `_close_row` |
| Selected rescan and bulk recheck of due/in-progress findings | Implemented | `backend/scanops/api/findings.py` `POST /rescan`, `/rescan-due`, `/rescan-command` |
| Column builder and CSV (Comma-Separated Values) / XLSX (Excel workbook) export | Implemented | `frontend/src/ui/ColumnBuilder.jsx`, `backend/scanops/api/findings.py` `GET /export` |
| Timeline heatmap | Implemented | `backend/scanops/api/heatmap.py`, `frontend/src/views/Heatmap.jsx` |
| Asset ledger import (xlsx/xls/csv) and IP (Internet Protocol) matching | Implemented | `frontend/src/lib/assetImport.js`, `backend/scanops/api/assets.py` `POST /bulk`, `/import` |
| Department notice generation and records | Implemented | `backend/scanops/api/notifications.py` |
| Sending notices externally (email etc.) | Not started | Intentionally absent for air-gapped use (module docstring of `backend/scanops/api/notifications.py`) |
| Audit log and audit report (xlsx) | Implemented | `backend/scanops/api/audit.py`, `backend/scanops/api/reports.py` `GET /audit` |
| Dashboard metrics | Implemented | `backend/scanops/api/dashboard.py`, `frontend/src/views/Dashboard.jsx` |
| Scan presets and standalone scanner sync | Implemented | `backend/scanops/api/presets.py` `POST /sync`, `scanner/scanops_scanner.py` |
| Standalone scanner (CLI (Command-Line Interface) and GUI (Graphical User Interface)) | Implemented | `scanner/scanops_scanner.py`, `scanner/scanops_scanner_gui.py` |
| Process watchdog | Partial | One-shot runs repair the truncated XML and ingest it without closing authority (`WATCHDOG_RC` branch in `backend/scanops/api/scans.py`); staged scans fail without ingesting (`rc != 0` branch in `_engine_worker`) |
| Scan progress display | Partial | Provided by polling `GET /{scan_id}/progress` and `/stages` instead of the SSE (Server-Sent Events) log stream in the design |
| Scan diff API (Application Programming Interface) `GET /api/diff` | Not started | No route; the same information is available through the heatmap (`/api/heatmap`) and finding history |
| Downloading scan artifacts from the web UI | Not started | No download route in `backend/scanops/api/scans.py` |
| Offline install packages (wheelhouse, all-in-one ZIP) | Implemented | `packaging/install.ps1`, `packaging/build_allinone.py`, `packaging/build_zip.py` |
| CI (Continuous Integration) | Implemented | `.github/workflows/ci.yml`, `runtime-e2e.yml`, `package-runtime-smoke.yml` |

### What was run for this check

- Backend tests (`python -m pytest -q`, Python 3.11): 1024 passed, 5 skipped, 1 failed. The failing `test_package_runtime_commands_have_a_hard_timeout` failed the same way before the personal-data cleanup and appears to be an environment issue (orphaned processes are not reaped in this container).
- Frontend tests (`npm test`): all 110 passed.
- A local server was started, the synthetic data in `test_samples/` plus `samples/scanA.xml` and `samples/scanB.xml` were imported, and the screens and rescan closure were checked. A web scan against `127.0.0.1` also ran to completion.

## Work history

Derived from `git log`; dates are in KST (Korea Standard Time, Asia/Seoul). The original commits mix `+0900` and `+0000` offsets, and all were converted to KST.

| Period | Main work |
|---|---|
| 2026-06-18 | Initial commit. Reliability, security and CI hardening, raw command scans, nmapParser scan builder port, asset ledger change preview |
| 2026-06-19 | Staged scan engine (`engine/`) and backend integration (`run-staged`), vulnerable-port rescans moved to the background engine, stage timeline UI |
| 2026-06-21 – 06-25 | Default scan profile tuning, purpose-evidence panel and timeline heatmap, repository size reduction, per-finding rescans with a result drawer, risk rule management merged |
| 2026-06-29 | Eight QA (Quality Assurance) rounds on the standalone scanner (QA-031 to QA-059 fixed; round 8 found nothing new) |
| 2026-07-21 – 07-29 | Integrated validation samples, scenarios and reports (`test_samples/`), broken XML import returns 400, reproducibility fixes |
| 2026-08-04 – 08-12 | Scan scope and control hardening, Server identity preserved, PowerShell 5 compatible offline installer, port/IP range exclusion and low-intensity scans, preset sync, Python 3.13 bundle |
| 2026-08-14 – 08-19 | TLS (Transport Layer Security) evidence recovery, status evidence display, per-port isolation of UDP (User Datagram Protocol) identification, closure audit tool, no closure for unobserved hosts, compliance evidence, assignee control, NSE (Nmap Scripting Engine) exposure signals, EOL in risk |
| 2026-08-21 – 08-25 | Per-host time limit replaced with a process watchdog, throughput flags reframed as load caps, unconfirmed observations folded, folder-level import grouping, latency trace panel, many review fixes (PR (Pull Request) #54 merged) |
| 2026-09-27 | Personal data removed from fixtures, samples and scripts; detail docs moved to `docs/`; README split into Korean/English with screenshots; progress record added |

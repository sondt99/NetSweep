# Changelog

All notable changes to NetSweep are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.2.0] - 2026-08-11

### Changed

- **Clean repository root**: single launcher `run.py`; all application code under `netsweep/`
- Removed temporary root compatibility shims (`main.py`, `lan_scanner.py`, `host_scanner.py`,
  `port_scanner.py`, `service_detector.py`, `config.py`, `scanner/`, `utils/`, `config_data/`)

### Breaking (shim users only)

- Do **not** run `python main.py` / `python lan_scanner.py` / `python host_scanner.py` anymore
- Use instead:
  - `python run.py` or `python -m netsweep` or `netsweep`
  - `netsweep-lan`, `netsweep-host`, `netsweep-sadp`
  - Library imports: `from netsweep…` only

### Documentation

- README and `docs/` updated for the clean layout and entrypoints

### Notes

- Package API (`netsweep.*`) and console scripts from 5.1.x remain the same
- Security limits, offline OUI, and in-process menu behavior unchanged from 5.1.0

## [5.1.0] - 2026-08-11

### Changed — professional package refactor

- Introduced installable **`netsweep`** package with layered layout:
  `cli` → `scan` → `net` / `config` / `policy` / `data` / `logging` / `report`
- Interactive menu runs scanners **in-process** (no subprocess hop)
- Shared **scope policy** (`netsweep.policy.scope`) for LAN and host confirmation
- Unified networking helpers under `netsweep.net.interfaces`
- Console scripts: `netsweep`, `netsweep-lan`, `netsweep-host`, `netsweep-sadp`
- Root modules remain **backward-compatible shims** for tests and old imports

### Documentation

- Full **README.md** rewrite for package-first install, CLI, security, and library use
- New **`docs/`** site: installation, quickstart, CLI, configuration, library API,
  architecture, scanning, security, performance, testing, experimental tools, FAQ,
  contributing

### Cleanup

- Removed root compatibility shims (`main.py`, `lan_scanner.py`, `host_scanner.py`, …)
- Single repo entrypoint: **`run.py`** → `netsweep.cli.menu`

## [5.0.0] - 2026-08-11

Hardening release from a multi-agent architecture, correctness, QA, and
Black Hat / DEF CON-style security & performance review. Closes issues
[#3](https://github.com/sondt99/NetSweep/issues/3)–[#22](https://github.com/sondt99/NetSweep/issues/22).

### Security

- **Enforce `SecurityConfig` at runtime**: `max_scan_targets`, `max_concurrent_connections`, `max_threads`, confirmation for large / non-private scopes (#5).
- **Global connection budget** so multi-host discovery cannot open thousands of FDs (#6).
- **Banner size cap (4 KiB)** and **redaction of `Set-Cookie` / `Authorization`** in service detection and exports (#8).
- Replace **`os.popen` ping** with `subprocess.run` argv lists for TTL/OS detection (#11).
- Offline **OUI vendor map** by default; online `macvendors` API is **opt-in** (`online_vendor_lookup`) (#13).
- Sanitize result path components; restrictive directory modes; atomic JSON writes (#8, #18).
- Real **SECURITY.md** with supported versions and reporting process (#16).
- Expanded **`.gitignore`** for logs, reports, results, device dumps (#14).
- `hikvision_sadp.py` no longer runs on import; CLI args only (#21).

### Fixed

- Config menu **reset** used the wrong type (`AttributeError`); now uses `ConfigManager` and saves (#3).
- LAN menu **`-v`** accepted by `lan_scanner` (#4).
- Soft **per-IP deadline** inside `scan_ip` (vendor/ports skipped when budget exhausted) (#7).
- UDP aggregator: confirmed **`open` no longer classified as closed**; `open|filtered` kept separate (#9).
- Host scanner **single ServiceDetector path**; export path printed from exporter (#10).
- **`/31`/`/32`** host enumeration; **`max_scan_targets`** refused for oversized CIDRs; chunked futures (#15).
- Port range validation (1–65535, no inverted ranges) (#19).
- Windows `ipconfig` only runs on Windows; safer socket `finally` closes (#18, #19).
- `config.py` vs `config/` shadowing resolved via **`config_data.ports`** (#12).

### Performance

- Connection-budgeted **batched** port probes under concurrent hosts (#6).
- Offline OUI avoids vendor API latency/429 storms on the hot path (#13).
- Reduced fixed sleeps in banner grab; soft IP budgets free workers (#7).
- Thread counts clamped to `security.max_threads` (#5).

### Changed

- Version **5.0.0**; package metadata via **`pyproject.toml`**.
- Dependencies cleaned: removed unused `ping3` / redundant `ipaddress` pin; **scapy optional**.
- Host menu passes timeout/threads from config.
- Default `ServiceDetector.scan_services(auto_export=False)` for library safety (CLI still exports).
- Upstream discovery messaging stresses authorized use only.

### Added

- `__version__.py`, `CHANGELOG.md`, `config_data/` package, `utils/connection_budget.py`, `utils/oui_db.py`.
- Regression tests for v5 security/correctness fixes (`tests/test_v5_security_fixes.py`).
- `lan_scanner` / `host_scanner` `--yes` to skip confirmations when automation is intentional.

### Documentation

- SECURITY.md rewritten for real disclosure workflow.
- README version aligned to 5.0.0 (honest security claims).

## [4.0.0] - prior

- Initial professional LAN/host scanner features, unit tests, and documentation baseline.

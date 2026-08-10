# Architecture

## Goals (v5.1+)

- Single installable package namespace: `netsweep`
- Clear layers with one-way dependencies
- CLI thin; scanners reusable as libraries
- Menu orchestration **in-process**
- Clean repository root: one launcher (`run.py`) + the `netsweep/` package

## Package map

```text
netsweep/
├── __init__.py          # public lazy exports + version
├── __main__.py          # python -m netsweep
├── __version__.py
├── cli/                 # argparse + interactive UX
│   ├── menu.py
│   ├── lan.py
│   ├── host.py
│   ├── sadp.py
│   └── config_cmd.py
├── scan/                # scan engines
│   ├── network.py       # NetworkScanner (LAN sweep)
│   ├── device.py        # DeviceInfo (liveness, MAC, ports, vendor)
│   ├── ports.py         # PortScanner (connect / SYN / UDP)
│   ├── service.py       # ServiceDetector + redaction
│   └── host_pipeline.py # re-exports host helpers
├── config/
│   ├── models.py        # dataclasses
│   └── manager.py       # load/save/validate/singleton
├── net/
│   ├── interfaces.py    # IP/MAC/networks/upstream
│   ├── budget.py        # connection semaphore
│   └── upstream.py      # re-export upstream helpers
├── policy/
│   └── scope.py         # max targets + confirmation
├── data/
│   ├── ports.py         # COMMON_PORTS
│   └── oui.py           # offline OUI DB
├── logging/
│   └── errors.py        # ErrorHandler, decorators
└── report/
    ├── export.py        # atomic JSON write
    └── table.py         # tabulate helpers
```

## Layering rules

```text
┌─────────────────────────────────────────┐
│  cli (menu, lan, host, sadp, config)    │
└───────────────────┬─────────────────────┘
                    │
┌───────────────────▼─────────────────────┐
│  scan (network, device, ports, service) │
└───────┬─────────────────────┬───────────┘
        │                     │
┌───────▼────────┐   ┌────────▼──────────┐
│ net / policy   │   │ config / data     │
│ logging/report │   │                   │
└────────────────┘   └───────────────────┘
```

- **`scan` never imports `cli`.**  
- **`cli` may import `scan`, `config`, `policy`, `logging`.**  
- **`data` and `config.models` are leaves** (no I/O except manager).  

## Runtime flows

### Menu → LAN

```text
cli.menu → cli.lan.run_from_argv → NetworkScanner.scan
                → DeviceInfo (alive, MAC, vendor, ports)
                → policy.enforce_lan_scope
                → net.budget (socket cap)
```

### Menu → Host

```text
cli.menu → cli.host.run_from_argv → TCP scan_ports
                → optional detect_os (ping TTL)
                → optional ServiceDetector (+ export)
                → policy.enforce_host_scope
```

### Library embedder

```text
User code → netsweep.scan.* / netsweep.config
         (no menu required)
```

## Repository root (clean)

| Path | Role |
|------|------|
| `run.py` | Thin launcher → `netsweep.cli.menu.main` |
| `netsweep/` | **All** application source |
| `tests/` | pytest suite |
| `docs/` | Documentation |
| `config/` | Optional data files only (e.g. `known_devices.json`) |

**How to start the app:**

```bash
python run.py
python -m netsweep
netsweep                 # after pip install -e .
```

Import **only** `netsweep.*` in new code.

## Design notes

### Connection budget

`netsweep.net.budget` exposes a process-wide `BoundedSemaphore` sized by `security.max_concurrent_connections`. Device port probes acquire slots so concurrent hosts cannot open unbounded FDs.

### Soft IP timeout

LAN workers apply a **deadline** inside `scan_ip` rather than relying on `Future.result(timeout=)` after `as_completed` (which cannot cancel in-flight work). Vendor/port enrichment may be skipped when the budget expires.

### Offline OUI

Vendor strings prefer `netsweep.data.oui` offline map. HTTP lookup to macvendors is **opt-in** to reduce privacy leakage and latency.

### Scope policy

`netsweep.policy.scope` centralizes:

- `max_scan_targets` enforcement  
- Confirmation for large subnets or non-private ranges/hosts  

### Presentation vs engine

`NetworkScanner` still prints tables/progress for operator UX. Export helpers live under `report/`. Future cleanups may push more presentation exclusively into `cli`.

## Testing architecture

- Tests import **`netsweep.*`** modules so monkeypatches hit real implementations.  
- `tests/conftest.py` isolates the global error-handler log path.  
- See [testing.md](testing.md).

## Related experimental code

- `netscan.sh` — parallel bash/nmap tool (not part of the Python package graph).  
- Documented in [experimental.md](experimental.md).

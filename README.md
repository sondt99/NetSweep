# NetSweep

**Professional network discovery and host scanning toolkit for Python**

[![Version](https://img.shields.io/badge/version-5.2.0-blue)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-202%20passed-brightgreen)](tests/)

> **Authorized use only.** Only scan systems and networks you own or have explicit written permission to assess. Unauthorized scanning may be illegal.

NetSweep helps you discover live hosts on a LAN, fingerprint devices (MAC / vendor / open ports / type), and deep-scan a single host (ports, banners, basic OS guess, SSL cert fields). It is packaged as the installable `netsweep` Python package with a menu UI and first-class CLIs.

**Full documentation:** [`docs/`](docs/README.md)

---

## Features

| Area | What you get |
|------|----------------|
| **LAN discovery** | Auto-detect local CIDRs, multi-threaded host sweep, progress bar, device table |
| **Device info** | Liveness (TCP probe / ping / ARP), MAC, offline OUI vendor map, type heuristics |
| **Host scan** | Port ranges / lists, multi-threaded TCP connect, optional OS + service detection |
| **Services** | Banner grab with size caps, cookie/auth redaction, SSL/TLS handshake probes |
| **Port engine** | TCP connect (default); optional SYN/UDP via Scapy (`pip install 'netsweep[scapy]'`) |
| **Safety** | Max targets / connection budget / thread caps, confirmation for large or public scopes |
| **Config** | `~/.netsweep/config.json` with validation and menu reset |
| **Export** | JSON / CSV / TXT (LAN); JSON per-target service reports (host) |
| **SADP helper** | Experimental Hikvision camera discovery (`netsweep-sadp`) |

---

## Quick start

```bash
# Clone and install (editable + dev tools)
git clone https://github.com/sondt99/NetSweep.git
cd NetSweep
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Interactive menu (any of these)
python run.py
python -m netsweep
netsweep

# LAN scan (example)
netsweep-lan -n 192.168.1.0/24 -o json -d scan_results

# Host scan (example — your lab only)
netsweep-host -t 192.168.1.10 -p 1-1000 --service-detection -v

# Tests
pytest tests/ -q
```

---

## Documentation map

| Doc | Contents |
|-----|----------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/installation.md](docs/installation.md) | Install, deps, optional Scapy, system tools |
| [docs/quickstart.md](docs/quickstart.md) | First scans and common workflows |
| [docs/cli.md](docs/cli.md) | All CLIs and flags |
| [docs/configuration.md](docs/configuration.md) | Config file, security limits, defaults |
| [docs/library-api.md](docs/library-api.md) | Import and embed NetSweep in Python |
| [docs/architecture.md](docs/architecture.md) | Package layout and layering |
| [docs/scanning.md](docs/scanning.md) | How LAN / host / ports / services work |
| [docs/security.md](docs/security.md) | Hardening, dual-use, authorized use |
| [docs/performance.md](docs/performance.md) | Tuning large scans and FD budgets |
| [docs/testing.md](docs/testing.md) | Running and extending tests |
| [docs/experimental.md](docs/experimental.md) | SADP helper and `netscan.sh` |
| [docs/faq.md](docs/faq.md) | Common questions |
| [docs/contributing.md](docs/contributing.md) | PR / issue workflow |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

## Package layout

```text
NetSweep/
├── run.py                    # Single repo launcher → netsweep.cli.menu
├── netsweep/                 # All application source (installable package)
│   ├── cli/                  # menu, lan, host, sadp, config_cmd
│   ├── scan/                 # NetworkScanner, DeviceInfo, PortScanner, ServiceDetector
│   ├── config/               # dataclasses + ConfigManager
│   ├── net/                  # interfaces, budget, upstream discovery
│   ├── policy/               # scope confirmation / limits
│   ├── data/                 # port map, offline OUI
│   ├── logging/              # ErrorHandler
│   ├── report/               # export / table helpers
│   ├── __main__.py           # python -m netsweep
│   └── __version__.py
├── docs/                     # User & developer documentation
├── tests/                    # pytest suite
├── config/                   # Optional data (e.g. known_devices.json) — not Python code
├── pyproject.toml
├── requirements.txt
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

**Layers (dependency direction):**

```text
cli  →  scan  →  net / config / policy / data
              ↘  logging / report
```

---

## CLI overview

| Command | Role |
|---------|------|
| `python -m netsweep` / `netsweep` | Interactive menu (LAN / host / config) |
| `netsweep-lan` | LAN/CIDR discovery |
| `netsweep-host` | Single-host port & service scan |
| `netsweep-sadp` | Experimental Hikvision SADP discovery |

**LAN (selected flags):**

```text
-n/--network CIDR     Network to scan (e.g. 192.168.1.0/24)
-t/--threads N        Worker threads (default from config, usually 50)
-T/--timeout SEC      Per-connect timeout (default 0.5)
--ip-timeout SEC      Soft wall-clock budget per IP (default 2.0)
-o json|csv|txt       Export format
-d/--output-dir DIR   Export directory (default scan_results)
-v/--verbose
-y/--yes              Skip large/public scope confirmation
```

**Host (selected flags):**

```text
-t/--target HOST      IP or hostname (IPv4)
-p/--ports RANGE      e.g. 1-1000 or 22,80,443
-T/--threads N
--timeout SEC
--os-detection
--service-detection
-v/--verbose
-y/--yes
```

Details: [docs/cli.md](docs/cli.md).

---

## Configuration (high level)

Config file: **`~/.netsweep/config.json`** (created on first use).

Important **security** knobs (enforced at runtime):

| Setting | Default | Effect |
|---------|---------|--------|
| `max_scan_targets` | 1000 | Refuse larger host enumerations |
| `max_concurrent_connections` | 200 | Global socket budget (FD safety) |
| `max_threads` | 200 | Clamp worker pools |
| `require_user_confirmation` | true | Prompt for large / non-private scopes |
| `online_vendor_lookup` | false | Offline OUI only unless enabled |
| `allow_public_targets` | false | Extra caution for non-RFC1918 targets |

Full reference: [docs/configuration.md](docs/configuration.md).

---

## Library usage

```python
from netsweep import get_config, NetworkScanner, PortScanner, ServiceDetector

# LAN sweep
scanner = NetworkScanner(
    network="192.168.1.0/24",
    num_threads=50,
    scan_timeout=0.5,
    assume_yes=True,  # automation only on authorized nets
)
results = scanner.scan(export_format="json")

# Single-host TCP connect scan
ps = PortScanner("192.168.1.10", timeout=1.0, verbose=True)
ps.tcp_connect_scan(range(1, 1025), threads=100)
print(ps.get_results())

# Service banners (auto_export defaults to False for library safety)
svc = ServiceDetector("192.168.1.10", timeout=2.0, verbose=True)
print(svc.scan_services([22, 80, 443], auto_export=False))
```

More examples: [docs/library-api.md](docs/library-api.md).

---

## Security & responsible use

- Prefer **private** targets; public / large CIDRs prompt for confirmation by default.
- Banners are **capped** and sensitive headers (`Set-Cookie`, `Authorization`) are **redacted** in exports.
- Vendor lookup uses an **offline OUI map** by default (no phone-home).
- Do **not** commit `logs/`, `results/`, or `scan_results/` (see `.gitignore`).
- Report tool vulnerabilities privately via [SECURITY.md](SECURITY.md).

Operator-focused notes: [docs/security.md](docs/security.md).

---

## Requirements

- **Python 3.8+**
- Core: `netifaces`, `getmac`, `requests`, `tabulate`, `tqdm`
- Optional: `scapy` for SYN/UDP (`pip install 'netsweep[scapy]'`) — typically needs root/`CAP_NET_RAW`
- Platform tools used when present: `ping`, `ip`/`arp`, optional `traceroute`/`tracepath`

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -q
pytest --cov=netsweep --cov-report=term-missing -q
```

See [docs/testing.md](docs/testing.md).

---

## Changelog & releases

- [CHANGELOG.md](CHANGELOG.md)
- GitHub releases: https://github.com/sondt99/NetSweep/releases

---

## Contributing

Bug reports and features via [GitHub Issues](https://github.com/sondt99/NetSweep/issues/new/choose) (templates provided).  
See [docs/contributing.md](docs/contributing.md).

---

## License

MIT © Thai Son Dinh — see [LICENSE](LICENSE).

---

## Disclaimer

NetSweep is a dual-use recon tool. The authors are not responsible for misuse. Always obtain authorization before scanning. Prefer lab or owned infrastructure for learning and development.

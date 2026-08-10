# Installation

## Requirements

| Requirement | Notes |
|-------------|--------|
| Python | **3.8+** (3.10–3.12 recommended) |
| OS | Linux (primary), macOS, Windows (some helpers are Windows-specific) |
| Privileges | **TCP connect** scans: normal user. **SYN/UDP** (Scapy): root or `CAP_NET_RAW` |
| Network tools | `ping` recommended; Linux `ip` / `arp` for neighbor table; optional `traceroute` / `tracepath` |

## Install from source (recommended)

```bash
git clone https://github.com/sondt99/NetSweep.git
cd NetSweep

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Runtime only
pip install -e .

# Runtime + pytest / coverage
pip install -e ".[dev]"

# Optional SYN/UDP engine
pip install -e ".[scapy]"
# or: pip install 'netsweep[scapy]'
```

### Dependency files

If you prefer classic requirements files:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # includes pytest
```

`pyproject.toml` is the authoritative packaging metadata for 5.1+.

## Verify install

```bash
python -c "from netsweep import __version__; print(__version__)"
python -m netsweep --help 2>/dev/null || python -c "from netsweep.cli.menu import main; print('menu ok')"
netsweep-lan --help
netsweep-host --help
pytest tests/ -q
```

## Console entry points

After `pip install -e .` (or a normal install), these commands are available when the venv is active:

| Script | Module |
|--------|--------|
| `netsweep` | `netsweep.cli.menu:main` |
| `netsweep-lan` | `netsweep.cli.lan:main` |
| `netsweep-host` | `netsweep.cli.host:main` |
| `netsweep-sadp` | `netsweep.cli.sadp:main` |

You can always use module form without scripts on `PATH`:

```bash
python -m netsweep
python -m netsweep.cli.lan -n 192.168.1.0/24
```

## Optional: Scapy (SYN / UDP)

```bash
pip install 'netsweep[scapy]'
# or: pip install scapy
```

- Used only by `PortScanner.syn_scan` / `udp_scan`.
- Default host CLI uses **TCP connect** and does **not** require Scapy.
- Without privileges, raw scans may report everything as filtered — see [FAQ](faq.md).

## System packages (examples)

**Debian/Ubuntu:**

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip iputils-ping iproute2 traceroute
# optional for scapy build deps on some systems:
# sudo apt install -y libpcap-dev
```

**Fedora:**

```bash
sudo dnf install python3-pip iputils iproute traceroute
```

**macOS:**

```bash
# ping/arp usually present; traceroute optional
brew install python
```

## Config directory

On first config load, NetSweep may create:

```text
~/.netsweep/config.json
```

See [configuration.md](configuration.md).

## Uninstall

```bash
pip uninstall netsweep
# optional: rm -rf ~/.netsweep
```

## Troubleshooting install

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: netsweep` | Activate venv; `pip install -e .` from repo root |
| `netifaces` build errors | Install system Python headers / use a binary wheel for your platform |
| Command `netsweep` not found | Use `python -m netsweep` or ensure venv `bin` is on `PATH` |
| Tests fail on import | Run from repo root with `pythonpath = ["."]` (set in `pyproject.toml`) |

Next: [Quick start](quickstart.md).

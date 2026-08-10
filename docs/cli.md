# CLI reference

All commands assume an activated environment with NetSweep installed (`pip install -e .`).

---

## `netsweep` / `python -m netsweep`

Interactive menu.

| Action | Behavior |
|--------|----------|
| LAN scan | Prompts for threads, timeout, export format/dir, verbose; runs `lan` in-process |
| Host scan | Prompts for target, ports, verbose, OS/service flags; passes config timeout/threads |
| Configuration | View config, error summary, reset defaults (saved to disk) |

No long-form argparse on the menu itself — use the dedicated CLIs for scripting.

---

## `netsweep-lan` / `python -m netsweep.cli.lan`

LAN / CIDR discovery scanner.

### Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-n`, `--network` | *(interactive)* | Target CIDR, e.g. `192.168.1.0/24`. Host-bits allowed (`192.168.1.5/24` normalized). |
| `--discover-upstream` | off | Traceroute-based upstream private network picker (authorized use only). |
| `-t`, `--threads` | config `max_workers` (50) | Concurrent host workers (clamped by `max_threads`). |
| `-T`, `--timeout` | config `timeout` (0.5) | Socket timeout for discovery probes. |
| `--ip-timeout` | `2.0` | Soft wall-clock budget per IP inside the worker (vendor/ports may be skipped). |
| `-o`, `--output` | none | Export: `json`, `csv`, or `txt`. |
| `-d`, `--output-dir` | `scan_results` | Directory for exports. |
| `-v`, `--verbose` | off | Extra diagnostics. |
| `-y`, `--yes` | off | Skip confirmation for large/public scopes. |

### Interactive mode

If `-n` and `--discover-upstream` are omitted:

1. Lists local interface networks.  
2. Options: pick number, `c` custom CIDR, `d` upstream discovery.  

### Examples

```bash
netsweep-lan -n 192.168.0.0/24 -o json
netsweep-lan -n 10.10.0.0/24 -t 30 -T 0.3 --ip-timeout 3 -o csv -d ./out
netsweep-lan --discover-upstream -o txt
```

### Exit behavior

- Ctrl+C stops with a message.  
- Invalid CIDR or scope policy violations print an error and exit non-zero when applicable.  

---

## `netsweep-host` / `python -m netsweep.cli.host`

Single-host TCP scanner with optional OS and service detection.

### Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | **required** | IPv4 address or hostname (IPv6 not supported). |
| `-p`, `--ports` | config `default_ports` (`1-1000`) | Range `A-B` or list `22,80,443` (not mixed). |
| `-T`, `--threads` | config `max_workers` | Connect-scan workers (clamped). |
| `--timeout` | config `timeout` | Per-port connect timeout. |
| `-v`, `--verbose` | off | Print open ports as found. |
| `--os-detection` | off | TTL-based OS guess via `ping`. |
| `--service-detection` | off | Banner/service detection via `ServiceDetector` (+ export). |
| `-y`, `--yes` | off | Skip public-target / large port-range confirmation. |

### Port range rules

- Valid: `1-1000`, `22,80,443`, `65535`  
- Invalid: empty, inverted (`1000-1`), out of 1–65535, mixed `22,80-90`  

### Examples

```bash
netsweep-host -t 192.168.1.1 -p 1-1024 -v
netsweep-host -t router.lab -p 22,80,443,8443 --service-detection --os-detection
netsweep-host -t 10.0.0.5 -p 1-65535 -T 200 -y   # large range; confirm policy may still apply without -y
```

### Note on flag letters

| Tool | `-t` means | Timeout flag |
|------|------------|--------------|
| **LAN** | threads | `-T` / `--timeout` |
| **Host** | **target** | `--timeout` (long option); `-T` is **threads** |

Prefer long options in scripts to avoid confusion.

---

## `netsweep-sadp` / `python -m netsweep.cli.sadp`

Experimental **Hikvision SADP** UDP discovery (port **37020**).

| Flag | Default | Description |
|------|---------|-------------|
| `--broadcast` | `255.255.255.255` | Broadcast destination |
| `--target` | *(none)* | Optional unicast (repeatable); **no hardcoded LAN IPs** |
| `--timeout` | `5.0` | Listen window (seconds) |

```bash
netsweep-sadp --timeout 5
netsweep-sadp --target 192.168.1.50 --broadcast 192.168.1.255
```

See [experimental.md](experimental.md).

---

## Config CLI

```bash
python -m netsweep.cli.config_cmd --show-config
python -m netsweep.cli.config_cmd --validate
python -m netsweep.cli.config_cmd --create-config /tmp/netsweep-demo.json
```

---

## Repo launcher

```bash
python run.py                 # same as interactive menu
```

---

## Output locations

| Tool | Default output |
|------|----------------|
| LAN export | `scan_results/scan_YYYYMMDD_HHMMSS.{json,csv,txt}` |
| Host service export | `results/<safe_target>/<target>_<timestamp>.json` |
| Logs (menu / ErrorHandler) | `logs/netsweep.log` (when logging is configured) |

Do not commit these directories (`.gitignore`).

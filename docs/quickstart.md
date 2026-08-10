# Quick start

Only scan networks and hosts you are **authorized** to test.

## 1. Install

```bash
cd NetSweep
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

See [installation.md](installation.md).

## 2. Interactive menu

```bash
python run.py
# or: python -m netsweep
```

Menu options:

1. **Scan Local Network** — pick interface CIDR, custom CIDR, or upstream discovery  
2. **Host Scanner** — single target ports / OS / services  
3. **Configuration** — view settings, error summary, reset defaults  
0. Exit  

The menu runs scanners **in-process** (no separate Python subprocess).

## 3. First LAN scan

Discover your local segment (example — replace with **your** network):

```bash
# List-driven interactive selection
netsweep-lan

# Explicit CIDR + JSON export
netsweep-lan -n 192.168.1.0/24 -t 50 -T 0.5 -o json -d scan_results
```

What happens:

1. Hosts in the CIDR are enumerated (subject to `max_scan_targets`).  
2. Each host is probed for liveness (common ports → ping → ARP/neighbor).  
3. Live hosts: MAC, offline vendor OUI, discovery port set, device type.  
4. Results print as a table; optional export under `scan_results/`.  

Large or non-private scopes prompt for confirmation unless you pass `-y` (use carefully).

## 4. First host scan

```bash
netsweep-host -t 192.168.1.1 -p 1-1000 -v

# With service banners + OS guess
netsweep-host -t 192.168.1.10 -p 22,80,443,8080 \
  --os-detection --service-detection -v
```

Service detection writes a redacted JSON report under `results/<target>/` when export is enabled by the CLI path.

## 5. Automation tip

For scripts on **known private** lab ranges:

```bash
netsweep-lan -n 10.0.0.0/24 -o json -y
netsweep-host -t 10.0.0.5 -p 1-1024 --service-detection -y
```

`-y` / `--yes` skips interactive confirmation. You remain responsible for authorization.

## 6. Config peek

```bash
python -m netsweep.cli.config_cmd --show-config
python -m netsweep.cli.config_cmd --validate
```

Or use menu → Configuration.

## 7. Run tests

```bash
pytest tests/ -q
```

## Suggested lab workflow

1. Build a small lab (VMs/containers on a private `/24`).  
2. LAN-scan the lab segment; export JSON.  
3. Host-scan interesting IPs with service detection.  
4. Review exports; ensure no secrets are committed.  
5. Tune `~/.netsweep/config.json` (threads, max targets, confirmation).  

Next: [CLI reference](cli.md) · [Configuration](configuration.md).

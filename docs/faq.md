# FAQ

## Authorization & legality

### Can I scan the public internet with NetSweep?

Technically some features accept remote hosts, but you must have **authorization**. Defaults discourage non-private targets. Unauthorized scanning can be illegal.

### What does “upstream discovery” do?

It traceroutes toward the internet and suggests private hop networks (e.g. shared building infrastructure). Only use this with permission.

---

## Installation & runtime

### `ModuleNotFoundError: No module named 'netsweep'`

Install from the repo root:

```bash
pip install -e .
```

### `netsweep: command not found`

Use `python -m netsweep` or ensure your virtualenv’s `bin` directory is on `PATH`.

### Why Python 3.8+?

Packaging and typing assumptions for 5.1; older 3.7 is no longer the supported floor.

---

## Scanning behavior

### Why is my `/32` scan empty / fixed?

Older versions scanned zero hosts for `/32`. Current code includes `/31` and `/32` addresses. Update to 5.0+.

### Why do I hit `max_scan_targets`?

Default cap is 1000 hosts. Raise it in `~/.netsweep/config.json` only if you accept the risk, or scan smaller CIDRs.

### Vendor is always “Unknown”

Offline OUI covers common vendors only. Enable `online_vendor_lookup` or pass `allow_online=True` in code (privacy tradeoff). Randomized MACs return `Randomized/Private MAC`.

### SYN/UDP shows everything filtered

Usually missing root privileges or Scapy. Use TCP connect scan, or install Scapy and run with appropriate capabilities.

### IPv6 target failed

IPv6 is **not supported** in 5.1. Use IPv4 or wait for a future release.

### Host `-t` vs LAN `-t`

| CLI | `-t` |
|-----|------|
| LAN | threads |
| Host | **target** |

Use long options in scripts: `--threads`, `--target`, `--timeout`.

---

## Security & privacy

### Are scan results safe to commit?

No. They can contain topology and residual banner data. `.gitignore` excludes typical output dirs.

### Does NetSweep phone home?

Not by default. Online MAC vendor lookup is opt-in. Scans themselves only talk to targets you specify (and optional vendor API if enabled).

### Session cookies appeared in old result JSON

Pre-5.0 banner export could store full HTTP bodies. Current redaction strips `Set-Cookie` / auth headers and caps size. Delete old artifacts.

---

## Development

### Where is the real source?

Under **`netsweep/`**. Root `*.py` files are shims.

### Tests patch old modules?

New tests should import `netsweep.*`. Existing suite was updated for 5.1.

### How do I report a bug?

Use GitHub issue templates: https://github.com/sondt99/NetSweep/issues/new/choose  

Security vulns: [SECURITY.md](../SECURITY.md).

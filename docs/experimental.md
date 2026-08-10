# Experimental tools

These are **not** part of the core `netsweep` library API surface. Use with care on authorized networks only.

---

## Hikvision SADP (`netsweep-sadp`)

### Purpose

Send a Hikvision **SADP** discovery probe over UDP and print responses (often XML device metadata).

### Usage

```bash
netsweep-sadp --timeout 5
netsweep-sadp --broadcast 192.168.1.255 --target 192.168.1.50
python -m netsweep.cli.sadp --timeout 3
```

### Library form

```python
from netsweep.cli.sadp import discover_sadp

responses = discover_sadp(broadcast="255.255.255.255", extra_targets=[], timeout=5.0)
for addr, data in responses:
    print(addr, data[:100])
```

### Notes

- Port **37020/UDP**  
- No authentication  
- May reveal serials/firmware — treat as sensitive  
- Not merged into LAN table export  
- Safe to import (side effects only under `main`)  

---

## `netscan.sh`

Standalone **bash** scanner using **nmap**, **curl**, and a local OUI map.

### Characteristics

- Requires **root** (script checks `EUID`)  
- Depends on `nmap`, `ip`, etc.  
- Separate report format (`netscan_report_*.txt/csv`)  
- Parallel product — not driven by `~/.netsweep/config.json`  

### Usage

```bash
sudo ./netscan.sh                 # auto /24 from default gateway
sudo ./netscan.sh 192.168.1.0/24
```

### When to use Python instead

| Need | Prefer |
|------|--------|
| Embed in Python apps | `netsweep` package |
| Configurable security limits | Python config |
| Tests / CI | Python pytest suite |
| nmap host discovery quality | `netscan.sh` or nmap directly |

### Future

`netscan.sh` may be moved to `contrib/` or retired once Python parity is enough. Do not treat it as the primary NetSweep interface.

---

## Root compatibility shims

Files like `main.py` and `lan_scanner.py` are thin wrappers for older docs and scripts. Prefer:

```bash
python -m netsweep
netsweep-lan
netsweep-host
```

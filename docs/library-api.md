# Library API

NetSweep 5.1+ is designed for embedding as well as CLI use.

## Import surface

```python
from netsweep import (
    __version__,
    get_config,           # lazy
    get_config_manager,   # lazy
    NetworkScanner,       # lazy
    DeviceInfo,           # lazy
    PortScanner,          # lazy
    ServiceDetector,      # lazy
)
```

Preferred explicit imports:

```python
from netsweep.scan.network import NetworkScanner
from netsweep.scan.device import DeviceInfo
from netsweep.scan.ports import PortScanner
from netsweep.scan.service import ServiceDetector, redact_banner
from netsweep.config import get_config, clamp_threads
from netsweep.net.interfaces import get_local_networks, get_local_ip
from netsweep.policy.scope import enforce_lan_scope, enforce_host_scope
```

## LAN discovery

```python
from netsweep.scan.network import NetworkScanner

scanner = NetworkScanner(
    network="192.168.1.0/24",
    num_threads=40,
    scan_timeout=0.5,
    ip_timeout=2.0,
    output_dir="scan_results",
    verbose=False,
    assume_yes=True,  # only on authorized automation
)
devices = scanner.scan(export_format="json")  # or "csv" / "txt" / None
for d in devices:
    print(d["ip"], d["mac"], d["vendor"], d["type"], d["ports"])
```

Each device dict includes: `ip`, `mac`, `vendor`, `ports`, `type`, `name`, `scan_time`.

Scope policy raises `ValueError` if host count exceeds `max_scan_targets`.

## Device probes

```python
from netsweep.scan.device import DeviceInfo

info = DeviceInfo(timeout=0.5)
print(info.check_device_alive("192.168.1.1"))
print(info.get_mac_address("192.168.1.1"))
print(info.get_vendor("00:0C:29:11:22:33"))  # offline OUI first
print(info.scan_open_ports("192.168.1.1", [22, 80, 443], timeout=0.5))
```

Online vendor API (privacy / latency):

```python
info.get_vendor(mac, allow_online=True)  # still subject to config
```

## Port scanner

```python
from netsweep.scan.ports import PortScanner

ps = PortScanner("192.168.1.10", timeout=1.0, verbose=True)
ps.tcp_connect_scan(range(1, 1025), threads=100)
print(ps.get_results())
# {"open": [...], "open|filtered": [...], "filtered": [...], "closed": [...]}

# Optional — requires scapy + privileges
# ps.syn_scan([80, 443], threads=20)
# ps.udp_scan([53, 161], threads=10)
```

Each public scan method **clears** previous result lists before running.

## Service detection

```python
from netsweep.scan.service import ServiceDetector

det = ServiceDetector("192.168.1.10", timeout=2.0, verbose=True)
results = det.scan_services([22, 80, 443], auto_export=False)
for r in results:
    print(r["port"], r["service"], r["version"], (r["banner"] or "")[:80])

# Export with redaction (safe path under results/)
path = det.export_to_json(results)
print(path, det.last_export_path)
```

`auto_export` defaults to **`False`** in the library for safe embedding. The host CLI enables export when `--service-detection` is used.

Banner helpers:

```python
from netsweep.scan.service import redact_banner, MAX_BANNER_BYTES
print(redact_banner("HTTP/1.1 200 OK\r\nSet-Cookie: SID=secret\r\n\r\nbody"))
```

## Host helpers

```python
from netsweep.cli.host import parse_port_range, resolve_host, scan_ports

ip = resolve_host("localhost")  # exits process on DNS failure when used as CLI helper
ports = parse_port_range("22,80,443")
open_list = scan_ports(ip, "22,80,443", timeout=1.0, threads=50, verbose=False)
```

For non-CLI embedding, catch `SystemExit` from `resolve_host` or resolve DNS yourself with `socket.gethostbyname`.

## Configuration

```python
from netsweep.config import get_config, get_config_manager

cfg = get_config()
print(cfg.security.max_scan_targets)

mgr = get_config_manager("/tmp/custom-netsweep.json")  # only honored if first call
```

## Networking utilities

```python
from netsweep.net.interfaces import (
    get_local_ip,          # Optional[str]
    get_local_ip_str,      # str, fallback 127.0.0.1
    get_local_mac,
    get_local_networks,
    get_upstream_networks,
)
```

## Connection budget

```python
from netsweep.net.budget import get_connection_semaphore, reset_connection_budget_for_tests

sem = get_connection_semaphore()  # BoundedSemaphore sized from config
# tests only:
reset_connection_budget_for_tests()
```

## Logging / errors

```python
from netsweep.logging.errors import get_error_handler, log_info, handle_errors

@handle_errors(default_return=None, reraise=False)
def work():
    ...

log_info("scan started")
print(get_error_handler().get_error_summary())
```

## Version

```python
from netsweep import __version__
assert __version__ == "5.1.0"  # or current
```

## Thread safety notes

- Do not share a single `PortScanner` instance across threads without external locking.  
- `DeviceInfo` caches (MAC/vendor) are lock-protected.  
- Connection budget is process-wide.  

## Deprecated import paths

These still work via shims but should not be used in new code:

```python
import host_scanner
from scanner.network_scanner import NetworkScanner
from service_detector import ServiceDetector
import config
```

Prefer `netsweep.*` imports.

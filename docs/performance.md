# Performance

## Defaults (typical)

| Parameter | Default |
|-----------|---------|
| LAN threads | 50 |
| Connect timeout | 0.5 s |
| Soft IP budget | 2.0 s |
| Discovery ports | ~100 common TCP ports |
| Max concurrent sockets | 200 |
| Max scan targets | 1000 |

## Rough capacity

| Scope | Expectation |
|-------|-------------|
| Empty/sparse `/24` | Tens of seconds |
| Typical home `/24` (API offline) | Often under a minute |
| Dense office `/24` | Longer; depends on live hosts + timeouts |
| `/16` | Not a supported happy path; hit `max_scan_targets` or raise carefully |
| Host `1-1000` fast-RST | Few seconds |
| Host + service detection | Adds sequential banner work per open port |

## Tuning knobs

### Faster empty / sparse LANs

- Ensure offline OUI (default) — avoid online vendor API.  
- Slightly lower timeout if your LAN is low-latency: `-T 0.2`.  
- Do not blindly raise threads without raising FD limits and `max_concurrent_connections`.  

### Safer dense scans

```json
"security": {
  "max_concurrent_connections": 200,
  "max_threads": 100
}
```

```bash
ulimit -n 4096
netsweep-lan -n 192.168.0.0/24 -t 30 -T 0.5
```

### Host full ranges

- Prefer staged scans: top ports first, then gaps.  
- Service detection is largely **sequential** per port — limit open-port count.  

### Soft IP timeout

`--ip-timeout` bounds enrichment effort per host. If vendor/port stages are cut short, lower discovery work or raise the budget.

## Bottlenecks (by design)

1. **Dead hosts** — still pay probe + optional ping/ARP cost.  
2. **Vendor API** (if enabled) — RTT and rate limits on the critical path.  
3. **Banner sleep/timeouts** — slow or malicious services.  
4. **FD exhaustion** — if budget is too high for `ulimit`.  

## Accuracy under load

If the connection budget is saturated, some ports may fail open and look closed. Prefer stable budgets over extreme concurrency.

## Comparison with `netscan.sh`

| | Python LAN | `netscan.sh` |
|--|------------|--------------|
| Discovery | TCP + ping + ARP | nmap `-sn` |
| Port set | Large discovery list | Smaller top set |
| Concurrency | High (budgeted) | Sequential nmap per host |
| Best for | Flexible Python inventory | L2 MAC completeness with nmap |

See [experimental.md](experimental.md).

## Profiling tips

```bash
# Time a lab /24
time netsweep-lan -n 192.168.56.0/24 -y -o json

# Watch FDs during scan (Linux)
ls /proc/$(pgrep -f netsweep-lan)/fd | wc -l
```

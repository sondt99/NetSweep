# Scanning deep dive

How NetSweep discovers hosts and services (v5.1 behavior).

---

## 1. LAN discovery (`NetworkScanner`)

### Inputs

- IPv4 CIDR (`strict=False` normalization)  
- Thread pool size, connect timeout, per-IP soft budget  
- Discovery port list from `config.network.common_ports_range`  

### Host enumeration

| Prefix | Addresses scanned |
|--------|-------------------|
| `/0`–`/30` | `network.hosts()` (excludes network/broadcast) |
| `/31`, `/32` | All addresses in the network |

Count is checked against `security.max_scan_targets` before work starts.

### Per-IP pipeline (`scan_ip`)

1. **Liveness** — `DeviceInfo.check_device_alive`  
   - Concurrent non-blocking TCP to common ports (80, 443, 22, …)  
   - Else ICMP `ping` (argv list, no shell)  
   - Else ARP / `ip neigh` with **real MAC** requirement (avoids false positives)  
2. **MAC** — local interface MAC if self; else `getmac`  
3. **Vendor** — offline OUI map; optional online API  
4. **Open ports** — discovery port set via selector + **connection budget** (batched)  
5. **Type** — heuristics on open service labels (camera RTSP, RDP, SSH, MQTT, …)  
6. **Name** — known-devices JSON if present  

If soft `ip_timeout` expires mid-pipeline, later stages may be skipped.

### Device type heuristics (summary)

| Signal | Label |
|--------|--------|
| Port 554 (RTSP) | Camera/Media Device |
| 80 + (443 or 8443) | Web Device / Web Server |
| 22 without 3389 | Linux/Unix Device |
| 3389 | Windows Device |
| 53 | DNS Server |
| 25/465/587 | Mail Server |
| 21 | FTP Server |
| 1883/8883 | IoT Device |
| else | Generic / Unknown |

### Concurrency model

- Outer: `ThreadPoolExecutor` over hosts (chunked submit).  
- Inner: non-blocking sockets + `selectors` / `select`, not nested thread pools per host.  
- Global semaphore limits simultaneous open sockets.  

---

## 2. Host TCP scan

### Flow

1. Resolve target to IPv4 (`socket.gethostbyname`; IPv6 rejected).  
2. Parse ports (`parse_port_range`).  
3. Scope confirmation (public / huge ranges).  
4. `ThreadPoolExecutor` TCP `connect_ex` per port.  
5. Service names from **static** `COMMON_PORTS` map (thread-safe; not `getservbyport`).  
6. Optional OS detection via ping TTL.  
7. Optional `ServiceDetector` on open ports.  

### OS guess (coarse)

| TTL range | Guess |
|-----------|--------|
| ≤ 64 | Linux/Unix |
| ≤ 128 | Windows |
| ≤ 255 | Solaris/AIX |
| + open 3389 / 22 | confidence adjusted |

This is **not** a full TCP/IP stack fingerprint (not Nmap OS DB).

---

## 3. PortScanner techniques

| Method | Privilege | Notes |
|--------|-----------|--------|
| `tcp_connect_scan` | User | Full handshake; reliable |
| `syn_scan` | Root/raw | Scapy; optional extra |
| `udp_scan` | Root/raw | Scapy; `open` vs `open\|filtered` separated |

Results buckets: `open`, `open|filtered`, `filtered`, `closed`.

---

## 4. Service detection

### Behavior

- Protocol-specific probes (HTTP, SSH greeting, Redis INFO, etc.).  
- SSL ports: TLS wrap with `CERT_NONE` (recon, not trust validation).  
- Banner receive: **max 4 KiB**, stop after HTTP headers when possible.  
- Export redacts `Set-Cookie`, `Authorization`, `Cookie`, etc.  

### Caveats

- Binary protocols may yield empty/decoded-lossy banners.  
- Aggressive probes (DB INFO commands) can trip IDS or stress fragile services — use only on authorized targets.  
- Certificate subject fields may be empty when verification is disabled depending on Python/OpenSSL builds.  

---

## 5. Hikvision SADP

UDP broadcast/unicast probe on port **37020**. Prints XML or hex dumps of replies. Not integrated into the main LAN pipeline. See [experimental.md](experimental.md).

---

## 6. Comparison: NetSweep vs Nmap

| Topic | NetSweep | Nmap |
|-------|----------|------|
| Focus | Python library + LAN inventory UX | Battle-tested multiprotocol scanner |
| SYN/UDP | Optional Scapy path | First-class |
| Scripts / NSE | No | Yes |
| Output ecosystem | JSON/CSV/TXT simple schemas | XML, greppable, many tools |
| Embed in Python | Native | Via subprocess / python-nmap |

NetSweep is complementary for Python automation and lab inventory — not a full Nmap replacement.

---

## 7. Accuracy tips

1. Raise `ulimit -n` if you increase connection budgets.  
2. Keep `max_concurrent_connections` sensible (e.g. 200–512).  
3. Offline OUI covers common vendors; enable online only if needed.  
4. Hosts that only answer rare ports may be missed by the short liveness set — use host scan with a wide `-p` when needed.  
5. Filtered networks: TCP connect may mark many ports filtered; that is expected.  

Next: [Performance](performance.md) · [Security](security.md).

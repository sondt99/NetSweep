# Security & responsible use

## Authorized use only

NetSweep can map networks and probe services. **Only scan systems you own or are explicitly authorized to test.** Unauthorized scanning may violate law and policy.

Upstream discovery (networks “above” your gateway) is especially sensitive — treat it as high-risk dual-use and obtain authorization first.

## Built-in safeguards (v5+)

| Control | Behavior |
|---------|----------|
| `max_scan_targets` | Blocks huge CIDR expansions |
| `max_concurrent_connections` | Limits simultaneous sockets (self-DoS / FD exhaustion) |
| `max_threads` | Clamps thread pools |
| Scope confirmation | Prompts for large or non-private scopes (unless `-y`) |
| Offline OUI | No third-party MAC phone-home by default |
| Banner cap + redaction | Limits memory and strips session cookies from exports |
| Shell-free system calls | Ping/TTL use argv lists, not shell strings |
| Safe export paths | Target-derived path components sanitized |

These reduce accidents and local abuse; they are **not** a substitute for operator discipline.

## What NetSweep is not

- Not a stealth APT framework  
- Not a guarantee of stealth (connect scans and pings are noisy)  
- Not a vulnerability exploit kit  
- Not IPv6-ready in 5.1  

## Secrets & artifacts

Never commit:

- `logs/`  
- `results/`  
- `scan_results/`  
- `netscan_report_*`  
- Device dumps (XML, etc.)  

Exports can still contain service banners and topology. Treat them as sensitive.

## Privilege model

| Mode | Privilege |
|------|-----------|
| LAN + TCP connect host scan | Normal user |
| SYN/UDP via Scapy | Root / `CAP_NET_RAW` |
| `netscan.sh` | Requires root (by design of that script) |

Prefer **not** running the entire menu as root. Use capabilities or run only the raw-scan code path privileged when needed.

## Reporting vulnerabilities **in NetSweep**

Use the process in [SECURITY.md](../SECURITY.md):

1. GitHub Security Advisory (private), or  
2. Maintainer contact via GitHub profile  

Do **not** open a public issue for unfixed security bugs with full exploit detail.  
Public issue form “Security concern” is for hardening ideas and process gaps only.

## Dual-use & distribution

MIT-licensed dual-use software. If you redistribute NetSweep:

- Keep LICENSE and SECURITY.md  
- Do not market it for unauthorized intrusion  
- Consider rate limits and confirmation defaults for your users  

## Hardening checklist for operators

- [ ] Confirm written authorization for the target scope  
- [ ] Keep `require_user_confirmation: true` in production ops  
- [ ] Keep `online_vendor_lookup: false` unless required  
- [ ] Run with least privilege  
- [ ] Store exports outside git; encrypt if needed  
- [ ] Review IDS/NAC impact before dense office scans  

## Related docs

- [configuration.md](configuration.md) — security knobs  
- [scanning.md](scanning.md) — probe behavior  
- [experimental.md](experimental.md) — SADP / bash scanner risks  

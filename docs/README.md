# NetSweep documentation

User and developer documentation for **NetSweep 5.1.x**.

Start with the [project README](../README.md) for a short overview, then use the guides below.

## Guides

| Document | Audience | Description |
|----------|----------|-------------|
| [Installation](installation.md) | Everyone | Python env, pip install, optional Scapy, OS tools |
| [Quick start](quickstart.md) | Operators | First LAN and host scans |
| [CLI reference](cli.md) | Operators | All entrypoints and flags |
| [Configuration](configuration.md) | Operators / admins | `~/.netsweep/config.json`, security limits |
| [Library API](library-api.md) | Developers | Embed scanners in Python code |
| [Architecture](architecture.md) | Developers | Package layout, layers, shims |
| [Scanning deep dive](scanning.md) | Operators / researchers | LAN, host, ports, services, SADP |
| [Security](security.md) | Everyone | Authorized use, hardening, secrets |
| [Performance](performance.md) | Operators | Threads, FD budget, large CIDRs |
| [Testing](testing.md) | Contributors | pytest, coverage, writing tests |
| [Experimental tools](experimental.md) | Advanced | SADP, `netscan.sh` |
| [FAQ](faq.md) | Everyone | Common questions |
| [Contributing](contributing.md) | Contributors | Issues, PRs, code style |

## Related root docs

- [CHANGELOG.md](../CHANGELOG.md) — version history  
- [SECURITY.md](../SECURITY.md) — vulnerability disclosure  
- [LICENSE](../LICENSE) — MIT  

## Version

Documentation targets **NetSweep 5.2.0** (package-first layout). Behavior from 5.0.x hardening still applies; see the changelog for details.

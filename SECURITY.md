# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 5.x     | :white_check_mark: |
| 4.x     | :x:                |
| < 4.0   | :x:                |

## Reporting a Vulnerability

NetSweep is a dual-use network scanning tool. Please report security issues **in the tool itself** (not “can I scan network X?” questions) privately:

1. Open a **private** [GitHub Security Advisory](https://github.com/sondt99/NetSweep/security/advisories/new) on this repository, **or**
2. Email the maintainer via the GitHub profile contact on [sondt99](https://github.com/sondt99).

Please include:

- Affected version / commit
- Description of the issue and impact
- Minimal reproduction steps (against your own lab only)

We aim to acknowledge reports within **7 days** and ship a fix or mitigation for confirmed High/Critical issues in a timely patch release.

### In scope

- Command injection, path traversal, insecure defaults in NetSweep code
- Unbounded resource use that can DoS the **scanner host**
- Leakage of secrets (cookies, credentials) into logs/exports without redaction
- Supply-chain issues in published dependencies

### Out of scope

- Misuse of NetSweep to scan networks without authorization
- Vulnerabilities in third-party devices discovered *by* scanning
- Issues requiring unrealistic local privilege already granted by the operator

## Responsible use

Only scan systems and networks you own or have explicit permission to test. Unauthorized scanning may be illegal. NetSweep enforces configurable target/connection limits and confirms large or non-private scopes by default; operators remain responsible for lawful use.

## Hardening notes (v5+)

- Shell-free ping/TTL probes (`subprocess` argv lists)
- Banner size caps and sensitive header redaction in exports
- Runtime enforcement of `max_scan_targets` and `max_concurrent_connections`
- Offline OUI vendor lookup preferred over third-party API
- Results/logs should not be committed (see `.gitignore`)

"""Host scan pure helpers (shared with CLI).

Prefer importing from ``netsweep.cli.host`` for the full CLI, or from here for
library-style orchestration helpers.
"""
from netsweep.cli.host import (  # noqa: F401
    detect_os,
    detect_services,
    get_service_banner,
    get_service_name,
    get_ttl,
    parse_port_range,
    resolve_host,
    scan_port,
    scan_ports,
)

__all__ = [
    "detect_os",
    "detect_services",
    "get_service_banner",
    "get_service_name",
    "get_ttl",
    "parse_port_range",
    "resolve_host",
    "scan_port",
    "scan_ports",
]

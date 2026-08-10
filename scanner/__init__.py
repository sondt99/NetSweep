"""Shim package scanner → netsweep.scan."""
from netsweep.scan.device import DeviceInfo
from netsweep.scan.network import DISCOVERY_PORT_SERVICES, NetworkScanner, _count_scan_hosts, _iter_scan_hosts

__all__ = [
    "DeviceInfo",
    "NetworkScanner",
    "DISCOVERY_PORT_SERVICES",
    "_count_scan_hosts",
    "_iter_scan_hosts",
]

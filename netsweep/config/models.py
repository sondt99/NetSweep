"""Configuration dataclasses for NetSweep."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""
    timeout: float = 0.5
    max_workers: int = 50
    retry_count: int = 3
    banner_grab_timeout: float = 1.0
    scan_delay: float = 0.1


@dataclass
class NetworkConfig:
    """Network-related configuration."""
    default_ports: str = "1-1000"
    common_ports_range: Optional[List[int]] = None
    exclude_ports: Optional[List[int]] = None
    interface_timeout: float = 2.0

    def __post_init__(self) -> None:
        if self.common_ports_range is None:
            self.common_ports_range = [
                7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80,
                81, 88, 106, 110, 111, 113, 119, 135, 139, 143,
                144, 179, 199, 389, 427, 443, 444, 445, 465, 513,
                514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
                990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110,
                1433, 1720, 1723, 1755, 1883, 1900, 2000, 2001,
                2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
                4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
                5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
                7070, 8000, 8008, 8009, 8080, 8081, 8443, 8883,
                8888, 9100, 9999, 10000, 32768, 49152, 49153,
                49154, 49155, 49156, 49157,
            ]
        if self.exclude_ports is None:
            self.exclude_ports = []


@dataclass
class OutputConfig:
    """Output and logging configuration."""
    default_output_dir: str = "scan_results"
    export_format: str = "json"
    verbose: bool = False
    show_progress: bool = True
    table_style: str = "grid"


@dataclass
class SecurityConfig:
    """Security and limits configuration (enforced at runtime by scanners)."""
    max_scan_targets: int = 1000
    max_concurrent_connections: int = 200
    max_threads: int = 200
    rate_limit_delay: float = 0.01
    require_user_confirmation: bool = True
    allow_public_targets: bool = False
    online_vendor_lookup: bool = False


@dataclass
class NetSweepConfig:
    """Main NetSweep configuration class."""
    scan: Optional[ScanConfig] = None
    network: Optional[NetworkConfig] = None
    output: Optional[OutputConfig] = None
    security: Optional[SecurityConfig] = None

    def __post_init__(self) -> None:
        if self.scan is None:
            self.scan = ScanConfig()
        if self.network is None:
            self.network = NetworkConfig()
        if self.output is None:
            self.output = OutputConfig()
        if self.security is None:
            self.security = SecurityConfig()

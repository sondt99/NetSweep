import ipaddress
import time
import os
import json
import csv
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from tqdm import tqdm

from utils.system_utils import get_local_ip, get_local_mac
from scanner.device_info import DeviceInfo
from config import get_config, clamp_threads
from config_data.ports import COMMON_PORTS

# Service names for the curated discovery port list.
DISCOVERY_PORT_SERVICES = dict(COMMON_PORTS)


def _iter_scan_hosts(network: ipaddress.IPv4Network):
    """Yield host addresses; for /31 and /32 include network addresses (hosts() is empty)."""
    if network.prefixlen >= 31:
        for addr in network:
            yield addr
    else:
        for addr in network.hosts():
            yield addr


def _count_scan_hosts(network: ipaddress.IPv4Network) -> int:
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2 if network.num_addresses >= 2 else network.num_addresses


class NetworkScanner:
    """Sweeps a CIDR network, classifying each responsive host by open ports/MAC/vendor."""

    def __init__(
        self,
        network: str,
        num_threads: int = 50,
        scan_timeout: float = 0.5,
        ip_timeout: float = 2.0,
        output_dir: str = "scan_results",
        verbose: bool = False,
        assume_yes: bool = False,
    ):
        self.network = str(ipaddress.ip_network(network, strict=False))
        self.num_threads = clamp_threads(num_threads)
        self.timeout = scan_timeout
        self.ip_timeout = ip_timeout
        self.devices_found = 0
        self.start_time = None
        self.known_devices = self._load_known_devices()
        self.results = []
        self.local_ip = get_local_ip()
        self.device_info = DeviceInfo(timeout=scan_timeout)
        self.skipped_ips = 0
        self.output_dir = output_dir
        self.verbose = verbose
        self.assume_yes = assume_yes

        self.discovery_ports = get_config().network.common_ports_range

        if not os.path.exists(output_dir):
            os.makedirs(output_dir, mode=0o700, exist_ok=True)

    def _load_known_devices(self) -> Dict[str, Dict[str, str]]:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        package_file = os.path.join(base, "config", "known_devices.json")
        cwd_file = os.path.join(os.getcwd(), "config", "known_devices.json")
        home_file = os.path.join(os.path.expanduser("~"), ".netsweep", "known_devices.json")

        default_devices = {
            "192.168.1.1": {"name": "Router", "type": "network"},
            "192.168.1.254": {"name": "Router", "type": "network"},
            "192.168.0.1": {"name": "Router", "type": "network"},
        }

        # Prefer CWD (tests/operator overrides), then home, then package path
        for path in (cwd_file, home_file, package_file):
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue
        return default_devices

    def scan_ip(self, ip) -> Optional[Dict[str, Any]]:
        deadline = time.monotonic() + self.ip_timeout
        try:
            is_alive = self.device_info.check_device_alive(ip)
            if not is_alive:
                return None

            cfg = get_config()
            delay = getattr(cfg.scan, "scan_delay", 0.1) or 0
            if delay > 0:
                time.sleep(min(delay, 0.1))

            mac = None
            if str(ip) == self.local_ip:
                mac = get_local_mac()
            else:
                if time.monotonic() < deadline:
                    mac = self.device_info.get_mac_address(str(ip))

            vendor = "N/A"
            if mac and time.monotonic() < deadline:
                # Prefer offline OUI; online only if configured and time remains
                remaining = deadline - time.monotonic()
                vendor = self.device_info.get_vendor(mac, allow_online=remaining > 0.5)
            elif mac:
                vendor = self.device_info.get_vendor(mac, allow_online=False)

            open_ports: List[int] = []
            if time.monotonic() < deadline:
                open_ports = self.device_info.scan_open_ports(
                    str(ip), self.discovery_ports, self.timeout
                )

            port_strings = [
                f"{port}({DISCOVERY_PORT_SERVICES.get(port, 'unknown')})" for port in open_ports
            ]
            device_type = self._determine_device_type(port_strings)

            device_name = "Unknown"
            if str(ip) in self.known_devices:
                device_name = self.known_devices[str(ip)].get("name", "Unknown")

            return {
                "ip": str(ip),
                "mac": mac if mac else "N/A",
                "vendor": vendor,
                "ports": ", ".join(port_strings) if port_strings else "N/A",
                "type": device_type,
                "name": device_name,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        except Exception:
            return None

    def _determine_device_type(self, open_ports: List[str]) -> str:
        if not open_ports:
            return "Unknown"

        ports_str = " ".join(open_ports)

        if "554(" in ports_str:
            return "Camera/Media Device"

        if "80(" in ports_str and ("443(" in ports_str or "8443(" in ports_str):
            if "8080(" in ports_str or "8888(" in ports_str:
                return "Web Server"
            return "Web Device"

        if "22(" in ports_str and "3389(" not in ports_str:
            return "Linux/Unix Device"

        if "3389(" in ports_str:
            return "Windows Device"

        if "53(" in ports_str:
            return "DNS Server"

        if "25(" in ports_str or "587(" in ports_str or "465(" in ports_str:
            return "Mail Server"

        if "21(" in ports_str:
            return "FTP Server"

        if "1883(" in ports_str or "8883(" in ports_str:
            return "IoT Device"

        return "Generic Device"

    def _enforce_scope(self, network: ipaddress.IPv4Network, total_hosts: int) -> None:
        cfg = get_config().security
        max_targets = max(1, int(cfg.max_scan_targets))

        if total_hosts > max_targets:
            raise ValueError(
                f"Network has {total_hosts} hosts which exceeds max_scan_targets={max_targets}. "
                f"Reduce the CIDR or raise security.max_scan_targets in ~/.netsweep/config.json."
            )

        # Confirmation for large or non-private scopes
        if cfg.require_user_confirmation and not self.assume_yes:
            needs_confirm = total_hosts > 256 or not (
                network.is_private or network.is_loopback
            )
            if needs_confirm:
                print(
                    f"\n[!] About to scan {total_hosts} addresses on {network}. "
                    "Only proceed if authorized."
                )
                ans = input("Continue? (y/N): ").strip().lower()
                if ans != "y":
                    raise SystemExit("Scan aborted by user.")

    def scan(self, export_format: Optional[str] = None) -> List[Dict[str, Any]]:
        print("\nScanning network, please wait...")
        self.start_time = time.time()
        network = ipaddress.ip_network(self.network, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 networks are supported in this release")

        total_hosts = _count_scan_hosts(network)
        self._enforce_scope(network, total_hosts)

        print(f"Network: {self.network}")
        print(f"Total hosts to scan: {total_hosts}")
        print(f"IP wall-clock budget: {self.ip_timeout}s per IP (soft deadline inside worker)")
        print(f"Thread pool size: {self.num_threads}")
        print(f"Max concurrent connections: {get_config().security.max_concurrent_connections}")

        # Chunked submit to avoid materializing huge Future lists for large (but allowed) nets
        hosts = list(_iter_scan_hosts(network))
        chunk_size = max(self.num_threads * 2, 50)

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            with tqdm(total=total_hosts, desc="Scanning progress", unit="host") as pbar:
                for i in range(0, len(hosts), chunk_size):
                    chunk = hosts[i : i + chunk_size]
                    futures = [executor.submit(self.scan_ip, ip) for ip in chunk]
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                self.results.append(result)
                                self.devices_found += 1
                        except Exception as e:
                            if self.verbose:
                                print(f"\nError during scan: {e}")
                        finally:
                            pbar.update(1)

        try:
            self.results.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
        except ValueError:
            self.results.sort(key=lambda x: x.get("ip", ""))

        headers = ["IP", "MAC", "Vendor", "Device Type", "Open Ports"]
        table_data = [
            [r["ip"], r["mac"], r["vendor"], r["type"], r["ports"]] for r in self.results
        ]

        print("\nScanning results:")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        duration = time.time() - self.start_time
        print(f"\nStatistics:")
        print(f"- Scanning time: {duration:.2f} seconds")
        print(f"- Number of devices found: {self.devices_found}")
        print(f"- IPs skipped due to timeout: {self.skipped_ips}")

        if export_format:
            self.export_results(export_format)

        return self.results

    def export_results(self, format_type: str) -> None:
        if not self.results:
            print("No devices found - skipping export.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_{timestamp}"

        try:
            if format_type.lower() == "json":
                path = f"{filename}.json"
                self._atomic_write_json(path, self.results)
                print(f"Results exported to {path}")

            elif format_type.lower() == "csv":
                path = f"{filename}.csv"
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    writer.writerows(self.results)
                print(f"Results exported to {path}")

            elif format_type.lower() == "txt":
                path = f"{filename}.txt"
                headers = ["IP", "MAC", "Vendor", "Device Type", "Open Ports"]
                table_data = [
                    [r["ip"], r["mac"], r["vendor"], r["type"], r["ports"]] for r in self.results
                ]
                with open(path, "w", encoding="utf-8") as f:
                    f.write(tabulate(table_data, headers=headers, tablefmt="grid"))
                print(f"Results exported to {path}")
        except OSError as e:
            print(f"Failed to export results: {e}")

    @staticmethod
    def _atomic_write_json(path: str, data: Any) -> None:
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".scan_", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

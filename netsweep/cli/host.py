#!/usr/bin/env python3
"""
Host Scanner Network - A comprehensive network host scanner
Inspired by nmap with enhanced capabilities
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import platform
import time
import concurrent.futures
from datetime import datetime
from typing import Iterable, List, Optional, Tuple

from netsweep.scan.service import ServiceDetector
from netsweep.config import get_config, clamp_threads
from netsweep.policy.scope import enforce_host_scope
from netsweep.data.ports import get_service_name as static_service_name

try:
    from netsweep.__version__ import __version__
except ImportError:
    __version__ = "5.2.0"

MAX_THREADS = 500
MAX_PORTS = 65535


def banner() -> None:
    """Display the host scanner CLI banner"""
    print(f"Advanced Host Scanner Network Tool (NetSweep v{__version__})")
    print("-" * 60)


def get_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    cfg = get_config()
    parser = argparse.ArgumentParser(description='Host Scanner Network - Advanced host scanning tool')
    parser.add_argument('-t', '--target', dest='target', help='Target host to scan (IP or domain)')
    parser.add_argument(
        '-p', '--ports', dest='ports',
        default=cfg.network.default_ports,
        help=f'Port range to scan (default: {cfg.network.default_ports})',
    )
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable verbose output')
    parser.add_argument(
        '--timeout', dest='timeout', type=float, default=cfg.scan.timeout,
        help=f'Timeout for connections (default: {cfg.scan.timeout})',
    )
    parser.add_argument(
        '-T', '--threads', dest='threads', type=int, default=cfg.scan.max_workers,
        help=f'Number of threads (default: {cfg.scan.max_workers})',
    )
    parser.add_argument('--os-detection', dest='os_detection', action='store_true', help='Enable OS detection')
    parser.add_argument('--service-detection', dest='service_detection', action='store_true', help='Enable service detection')
    parser.add_argument(
        '--yes', '-y', dest='assume_yes', action='store_true',
        help='Skip confirmation prompts for large port ranges',
    )

    return parser.parse_args()


def resolve_host(target: str) -> str:
    """Resolve hostname to IPv4 address. Rejects empty and IPv6-only inputs with a clear error."""
    target = (target or "").strip()
    if not target:
        print("[-] Error: empty target")
        sys.exit(1)

    # Prefer explicit IPv4 validation
    try:
        addr = ipaddress.ip_address(target)
        if isinstance(addr, ipaddress.IPv6Address):
            print("[-] Error: IPv6 targets are not supported in this release (IPv4 only).")
            sys.exit(1)
        return str(addr)
    except ValueError:
        pass

    try:
        ip_address = socket.gethostbyname(target)
        print(f"[+] Target hostname: {target} resolves to {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {target}")
        sys.exit(1)


def parse_port_range(port_range: str) -> List[int]:
    """Parse a port range string into a list of ports (1-65535).

    Accepts a dash range ("1-1000") or a comma-separated list ("22,80,443").
    Raises ValueError on invalid input.
    """
    if not port_range or not str(port_range).strip():
        raise ValueError("Port range is empty")

    port_range = str(port_range).strip()
    ports: List[int] = []

    if "-" in port_range and "," not in port_range:
        parts = port_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid port range: {port_range}")
        start_port, end_port = int(parts[0]), int(parts[1])
        if start_port > end_port:
            raise ValueError(f"Inverted port range: {port_range}")
        if start_port < 1 or end_port > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        ports = list(range(start_port, end_port + 1))
    else:
        for token in port_range.split(","):
            token = token.strip()
            if not token:
                raise ValueError(f"Invalid port list: {port_range}")
            if "-" in token:
                raise ValueError("Mixed comma and range syntax is not supported; use either 1-1000 or 22,80,443")
            p = int(token)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.append(p)

    if not ports:
        raise ValueError("No ports to scan")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports (max {MAX_PORTS})")
    return ports


def get_service_name(port: int) -> str:
    """Get service name for a port using a thread-safe static map."""
    return static_service_name(port)


def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Scan a single port"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = get_service_name(port)
            return port, True, service
        return port, False, None
    except OSError:
        return port, False, None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan_ports(ip: str, port_range: str, timeout: float, threads: int, verbose: bool) -> List[Tuple[int, str]]:
    """Scan ports using multi-threading"""
    print(f"[+] Scanning ports {port_range} on {ip}...")

    ports = parse_port_range(port_range)
    threads = clamp_threads(min(threads, MAX_THREADS))

    open_ports: List[Tuple[int, str]] = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service or "unknown"))
                if verbose:
                    print(f"[+] Port {port}/tcp is open - {service}")

    scan_time = time.time() - start_time

    print(f"[+] Scan completed in {scan_time:.2f} seconds")
    print(f"[+] Found {len(open_ports)} open ports")

    if open_ports:
        print("\nPORT     STATE  SERVICE")
        for port, service in sorted(open_ports):
            print(f"{port:<8} open   {service}")

    return open_ports


def detect_os(ip: str, open_ports: List[Tuple[int, str]]) -> str:
    """Attempt to detect the operating system"""
    print("\n[+] Attempting OS detection...")

    ttl = get_ttl(ip)

    if ttl is None:
        print("[-] Could not determine OS (TTL detection failed)")
        return "Unknown"

    os_guess = "Unknown"
    confidence = "Low"

    if ttl <= 64:
        os_guess = "Linux/Unix"
        confidence = "Medium"
    elif ttl <= 128:
        os_guess = "Windows"
        confidence = "Medium"
    elif ttl <= 255:
        os_guess = "Solaris/AIX"
        confidence = "Low"

    port_nums = [p[0] for p in open_ports]
    if 3389 in port_nums:
        if os_guess == "Windows":
            confidence = "High"
        else:
            os_guess = "Windows or Linux with RDP"

    if 22 in port_nums:
        if os_guess == "Linux/Unix":
            confidence = "High"

    print(f"[+] OS detection results: {os_guess} (Confidence: {confidence})")
    return os_guess


def get_ttl(ip: str) -> Optional[int]:
    """Get TTL value using ping (argv list — no shell)."""
    try:
        # Only allow valid IP addresses into the process argv
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    try:
        is_windows = platform.system().lower() == "windows"
        if is_windows:
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
        )
        response = result.stdout or ""
        ttl_index = response.lower().find("ttl=")
        if ttl_index != -1:
            return int(response[ttl_index + 4 :].split()[0])
        return None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def get_service_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """Legacy banner grab (kept for unit tests / light probes). Prefer ServiceDetector."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in (80, 443, 8080):
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port not in (22, 21, 25, 587):
            sock.send(b"\r\n")
        banner_bytes = sock.recv(1024)
        return banner_bytes.decode("utf-8", errors="ignore")
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def detect_services(
    ip: str, open_ports: List[Tuple[int, str]], timeout: float
) -> List[Tuple[int, str, str, Optional[str]]]:
    """Legacy service detection helper (tests). Host main() uses ServiceDetector only."""
    print("\n[+] Performing service detection...")
    enhanced_ports = []
    for port, service in open_ports:
        service_banner = get_service_banner(ip, port, timeout)
        version = "unknown"
        if service_banner:
            try:
                if "SSH" in service_banner:
                    version = service_banner.split()[0]
                elif "HTTP" in service_banner:
                    version = "HTTP Server"
                    if "Apache/" in service_banner:
                        version = f"Apache {service_banner.split('Apache/')[1].split()[0]}"
                    elif "nginx/" in service_banner:
                        version = f"nginx {service_banner.split('nginx/')[1].split()[0]}"
            except (IndexError, ValueError):
                version = "unknown"
            print(f"[+] Port {port}/{service}: {version} - Banner: {service_banner.strip()[:80]}")
        else:
            print(f"[+] Port {port}/{service}: {version}")
        enhanced_ports.append((port, service, version, service_banner))
    return enhanced_ports


def _confirm_scope(ip: str, port_count: int, assume_yes: bool) -> None:
    """Shared scope policy."""
    enforce_host_scope(ip, port_count, assume_yes=assume_yes)



def run_from_argv(argv: list) -> None:
    """Run host CLI with an explicit argv list (excluding program name)."""
    import sys
    old = sys.argv
    try:
        sys.argv = ["netsweep-host"] + list(argv)
        main()
    finally:
        sys.argv = old


def main() -> None:
    """Main function"""
    banner()
    args = get_arguments()

    if not args.target:
        print("[-] Error: Target host is required. Use -t or --target to specify.")
        sys.exit(1)

    print(f"[+] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ip = resolve_host(args.target)

    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    _confirm_scope(ip, len(ports), args.assume_yes)

    threads = clamp_threads(args.threads)
    open_ports = scan_ports(ip, args.ports, args.timeout, threads, args.verbose)

    if args.os_detection:
        detect_os(ip, open_ports)

    if args.service_detection:
        if open_ports:
            print("\n[+] Performing service detection on open ports...")
            detector = ServiceDetector(ip, timeout=args.timeout, verbose=args.verbose)
            results = detector.scan_services([port for port, _ in open_ports], auto_export=True)
            # Prefer path from exporter
            export_path = detector.last_export_path
            if export_path:
                print(f"\n[+] Scan results saved to {export_path}")
            else:
                print("\n[+] Service detection completed")
            _ = results
        else:
            print("\n[+] No open ports for service detection")

    print(f"\n[+] Scan completed for {args.target} ({ip}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()

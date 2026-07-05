#!/usr/bin/env python3
"""
Host Scanner Network - A comprehensive network host scanner
Inspired by nmap with enhanced capabilities
"""

import argparse
import socket
import sys
import os
import platform
import time
import concurrent.futures
from datetime import datetime
from typing import Iterable, List, Optional, Tuple
from service_detector import ServiceDetector


def banner() -> None:
    """Display the host scanner CLI banner"""
    print("Advanced Host Scanner Network Tool")
    print("-" * 60)


def get_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Host Scanner Network - Advanced host scanning tool')
    parser.add_argument('-t', '--target', dest='target', help='Target host to scan (IP or domain)')
    parser.add_argument('-p', '--ports', dest='ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', dest='timeout', type=float, default=1.0, help='Timeout for connections (default: 1.0)')
    parser.add_argument('-T', '--threads', dest='threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--os-detection', dest='os_detection', action='store_true', help='Enable OS detection')
    parser.add_argument('--service-detection', dest='service_detection', action='store_true', help='Enable service detection')

    return parser.parse_args()


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address"""
    try:
        ip_address = socket.gethostbyname(target)
        print(f"[+] Target hostname: {target} resolves to {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {target}")
        sys.exit(1)


def parse_port_range(port_range: str) -> Iterable[int]:
    """Parse a port range string into an iterable of ports.

    Accepts either a dash range ("1-1000") or a comma-separated list ("22,80,443").
    """
    if '-' in port_range:
        start_port, end_port = map(int, port_range.split('-'))
        return range(start_port, end_port + 1)
    return [int(p) for p in port_range.split(',')]


def get_service_name(port: int) -> str:
    """Get service name for a port"""
    try:
        service = socket.getservbyport(port)
        return service
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = get_service_name(port)
            sock.close()
            return port, True, service
        sock.close()
        return port, False, None
    except OSError:
        return port, False, None


def scan_ports(ip: str, port_range: str, timeout: float, threads: int, verbose: bool) -> List[Tuple[int, str]]:
    """Scan ports using multi-threading"""
    print(f"[+] Scanning ports {port_range} on {ip}...")

    ports = parse_port_range(port_range)

    open_ports = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))
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

    # Basic OS detection based on TTL and port signatures
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

    # Improve detection based on open ports
    if 3389 in [p[0] for p in open_ports]:
        if os_guess == "Windows":
            confidence = "High"
        else:
            os_guess = "Windows or Linux with RDP"

    if 22 in [p[0] for p in open_ports]:
        if os_guess == "Linux/Unix":
            confidence = "High"

    print(f"[+] OS detection results: {os_guess} (Confidence: {confidence})")
    return os_guess

def get_ttl(ip: str) -> Optional[int]:
    """Get TTL value using ping"""
    try:
        if platform.system().lower() == "windows":
            ping_cmd = f"ping -n 1 {ip}"
        else:
            ping_cmd = f"ping -c 1 {ip}"

        response = os.popen(ping_cmd).read()
        # Linux/macOS ping prints lowercase "ttl=NN"; only Windows uses "TTL=".
        # A case-sensitive search here always misses on non-Windows, so
        # detect_os() silently failed on every host on those platforms.
        ttl_index = response.lower().find("ttl=")
        if ttl_index != -1:
            ttl = int(response[ttl_index+4:].split()[0])
            return ttl
        return None
    except (OSError, ValueError):
        return None

def detect_services(ip: str, open_ports: List[Tuple[int, str]], timeout: float) -> List[Tuple[int, str, str, Optional[str]]]:
    """Perform deeper service detection"""
    print("\n[+] Performing service detection...")

    enhanced_ports = []
    for port, service in open_ports:
        service_banner = get_service_banner(ip, port, timeout)
        version = "unknown"

        if service_banner:
            # Try to identify service version from banner
            if "SSH" in service_banner:
                version = service_banner.split()[0]
            elif "HTTP" in service_banner:
                version = "HTTP Server"
                if "Apache" in service_banner:
                    version = f"Apache {service_banner.split('Apache/')[1].split()[0]}"
                elif "nginx" in service_banner:
                    version = f"nginx {service_banner.split('nginx/')[1].split()[0]}"

            print(f"[+] Port {port}/{service}: {version} - Banner: {service_banner.strip()}")
        else:
            print(f"[+] Port {port}/{service}: {version}")

        enhanced_ports.append((port, service, version, service_banner))

    return enhanced_ports

def get_service_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """Get service banner for a port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send different probes based on common ports
        if port == 80 or port == 443 or port == 8080:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 22:
            # SSH will send banner automatically
            pass
        elif port == 21:
            # FTP will send banner automatically
            pass
        elif port == 25 or port == 587:
            # SMTP will send banner automatically
            pass
        else:
            # Generic probe
            sock.send(b"\r\n")

        banner_bytes = sock.recv(1024)
        sock.close()
        return banner_bytes.decode('utf-8', errors='ignore')
    except OSError:
        return None

def main() -> None:
    """Main function"""
    banner()
    args = get_arguments()

    if not args.target:
        print("[-] Error: Target host is required. Use -t or --target to specify.")
        sys.exit(1)

    print(f"[+] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Resolve hostname to IP
    ip = resolve_host(args.target)

    # Scan ports
    open_ports = scan_ports(ip, args.ports, args.timeout, args.threads, args.verbose)

    # OS detection if enabled
    if args.os_detection:
        detect_os(ip, open_ports)

    # Service detection if enabled
    if args.service_detection and open_ports:
        detect_services(ip, open_ports, args.timeout)

    print(f"\n[+] Scan completed for {args.target} ({ip}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if args.service_detection:
        print("\n[+] Performing service detection on open ports...")
        detector = ServiceDetector(ip, timeout=args.timeout, verbose=args.verbose)

        # Use auto_export=True to automatically export results
        detector.scan_services([port for port, _ in open_ports], auto_export=True)


        # No need to manually call export_to_json as it's done automatically
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        print(f"\n[+] Scan results saved to results/{ip}/{ip}_{timestamp}.json")

if __name__ == "__main__":
    main()
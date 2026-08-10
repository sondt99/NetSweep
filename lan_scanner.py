import os
import ipaddress
import argparse
import sys
from typing import List, Optional

from scanner.network_scanner import NetworkScanner
from utils.network_utils import get_local_networks, get_upstream_networks
from config import get_config, clamp_threads

try:
    from __version__ import __version__
except ImportError:
    __version__ = "5.0.0"


def _prompt_custom_network() -> Optional[str]:
    """Prompt for a network in CIDR notation, re-asking until valid or cancelled."""
    while True:
        raw = input("Enter network in CIDR notation (e.g. 192.168.1.0/24), or blank to cancel: ").strip()
        if not raw:
            return None
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            print("Invalid CIDR. Example of a valid value: 192.168.1.0/24")


def _prompt_upstream_network() -> Optional[str]:
    """Auto-discover reachable upstream networks and let the user pick one."""
    print("\nTracing route to discover upstream networks (this may take a few seconds)...")
    print("WARNING: Only scan upstream networks you are authorized to assess.")
    upstream = get_upstream_networks()

    if not upstream:
        print("No upstream networks found (traceroute tool missing, or the gateway")
        print("blocks the trace). You can still enter a network manually.")
        return _prompt_custom_network()

    print("\nDiscovered upstream networks (reachable via the gateway):")
    for idx, net in enumerate(upstream, 1):
        print(f"{idx}. {net['network']} (via hop {net['via']})")

    while True:
        raw = input("\nSelect an upstream network to scan (number), or blank to cancel: ").strip()
        if not raw:
            return None
        try:
            choice = int(raw) - 1
            if 0 <= choice < len(upstream):
                return upstream[choice]["network"]
        except ValueError:
            pass
        print("Invalid choice!")


def select_network(networks: List[dict]) -> Optional[str]:
    """Interactively pick a network to scan."""
    if networks:
        print("\nAvailable networks:")
        for idx, net in enumerate(networks, 1):
            print(f"{idx}. {net['network']} (Interface: {net['interface']})")
    else:
        print("\nNo local interface networks detected.")

    print("\nOther options:")
    print("  c. Enter a custom network manually (CIDR, e.g. 192.168.1.0/24)")
    print("  d. Auto-discover upstream networks (only with authorization)")

    while True:
        choice = input("\nSelect network to scan (number, or c/d): ").strip().lower()

        if choice == "c":
            result = _prompt_custom_network()
            if result:
                return result
            continue

        if choice == "d":
            result = _prompt_upstream_network()
            if result:
                return result
            continue

        try:
            index = int(choice) - 1
            if 0 <= index < len(networks):
                return networks[index]["network"]
        except ValueError:
            pass
        print("Invalid choice! Enter a listed number, or 'c'/'d'.")


def main() -> None:
    cfg = get_config()
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-n", "--network", help="Network to scan (CIDR format, e.g., 192.168.1.0/24)")
    parser.add_argument(
        "--discover-upstream",
        action="store_true",
        help="Auto-discover reachable upstream networks (authorized use only)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=cfg.scan.max_workers,
        help=f"Number of threads (default: {cfg.scan.max_workers})",
    )
    parser.add_argument("-o", "--output", choices=["json", "csv", "txt"], help="Export format (json, csv, txt)")
    parser.add_argument(
        "-d", "--output-dir", default=cfg.output.default_output_dir,
        help=f"Output directory for scan results (default: {cfg.output.default_output_dir})",
    )
    parser.add_argument(
        "-T", "--timeout", type=float, default=cfg.scan.timeout,
        help=f"Scan timeout in seconds (default: {cfg.scan.timeout})",
    )
    parser.add_argument(
        "--ip-timeout", type=float, default=2.0,
        help="Maximum wall-clock budget per IP in seconds (default: 2.0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--yes", "-y", dest="assume_yes", action="store_true",
        help="Skip confirmation for large or non-private scopes",
    )

    args = parser.parse_args()

    try:
        print(f"\n=== Advanced Network Scanner v{__version__} ===")

        if args.network:
            try:
                network = str(ipaddress.ip_network(args.network, strict=False))
            except ValueError as e:
                print(f"Invalid network CIDR: {e}")
                sys.exit(1)
        elif args.discover_upstream:
            network = _prompt_upstream_network()
            if not network:
                print("No network selected.")
                return
        else:
            networks = get_local_networks()
            network = select_network(networks)
            if not network:
                print("No network selected.")
                return

        if args.output and not os.path.exists(args.output_dir):
            os.makedirs(args.output_dir, mode=0o700, exist_ok=True)

        threads = clamp_threads(args.threads)
        scanner = NetworkScanner(
            network=network,
            num_threads=threads,
            scan_timeout=args.timeout,
            ip_timeout=args.ip_timeout,
            output_dir=args.output_dir,
            verbose=args.verbose,
            assume_yes=args.assume_yes,
        )

        scanner.scan(export_format=args.output)

        if args.output:
            print(f"\nResults exported to {args.output_dir} directory in {args.output} format.")

    except KeyboardInterrupt:
        print("\n\nScanning stopped by user!")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

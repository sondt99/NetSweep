import os
import ipaddress
import argparse
from typing import List, Optional
from scanner.network_scanner import NetworkScanner
from utils.network_utils import get_local_networks, get_upstream_networks


def _prompt_custom_network() -> Optional[str]:
    """Prompt for a network in CIDR notation, re-asking until valid or cancelled."""
    while True:
        raw = input("Enter network in CIDR notation (e.g. 192.168.1.0/24), or blank to cancel: ").strip()
        if not raw:
            return None
        try:
            # strict=False lets the user type a host address (192.168.1.5/24) and
            # still get the surrounding network, matching how NetworkScanner treats it.
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            print("Invalid CIDR. Example of a valid value: 192.168.1.0/24")


def _prompt_upstream_network() -> Optional[str]:
    """Auto-discover reachable upstream networks and let the user pick one."""
    print("\nTracing route to discover upstream networks (this may take a few seconds)...")
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
    """Interactively pick a network to scan.

    Offers the locally-attached interface networks plus two extras: entering a
    custom CIDR by hand, and auto-discovering upstream networks (the routers above
    the gateway, which never show up as local interfaces). Returns the chosen CIDR
    string, or None if the user cancels.
    """
    if networks:
        print("\nAvailable networks:")
        for idx, net in enumerate(networks, 1):
            print(f"{idx}. {net['network']} (Interface: {net['interface']})")
    else:
        print("\nNo local interface networks detected.")

    print("\nOther options:")
    print("  c. Enter a custom network manually (CIDR, e.g. 192.168.1.0/24)")
    print("  d. Auto-discover upstream networks (landlord/gateway side)")

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
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-n", "--network", help="Network to scan (CIDR format, e.g., 192.168.1.0/24)")
    parser.add_argument("--discover-upstream", action="store_true",
                        help="Auto-discover reachable upstream networks (routers above the gateway) and pick one to scan")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("-o", "--output", choices=["json", "csv", "txt"], help="Export format (json, csv, txt)")
    parser.add_argument("-d", "--output-dir", default="scan_results", help="Output directory for scan results")
    parser.add_argument("-T", "--timeout", type=float, default=0.5, help="Scan timeout in seconds (default: 0.5)")
    parser.add_argument("--ip-timeout", type=float, default=2.0, help="Maximum time to spend on a single IP in seconds (default: 2.0)")

    args = parser.parse_args()

    try:
        print("\n=== Advanced Network Scanner v4.0 ===")

        if args.network:
            network = args.network
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

        # Create output directory if it doesn't exist
        if args.output and not os.path.exists(args.output_dir):
            os.makedirs(args.output_dir)

        scanner = NetworkScanner(
            network=network,
            num_threads=args.threads,
            scan_timeout=args.timeout,
            ip_timeout=args.ip_timeout,
            output_dir=args.output_dir
        )

        scanner.scan(export_format=args.output)

        if args.output:
            print(f"\nResults exported to {args.output_dir} directory in {args.output} format.")

    except KeyboardInterrupt:
        print("\n\nScanning stopped by user!")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()

import os
import argparse
from scanner.network_scanner import NetworkScanner
from utils.network_utils import get_local_networks

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-n", "--network", help="Network to scan (CIDR format, e.g., 192.168.1.0/24)")
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
        else:
            networks = get_local_networks()
            
            if not networks:
                print("No network found!")
                return
    
            print("\nAvailable networks:")
            for idx, net in enumerate(networks, 1):
                print(f"{idx}. {net['network']} (Interface: {net['interface']})")
    
            while True:
                try:
                    choice = int(input("\nSelect network to scan (enter number): ")) - 1
                    if 0 <= choice < len(networks):
                        network = networks[choice]['network']
                        break
                    print("Invalid choice!")
                except ValueError:
                    print("Please enter a number!")
        
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
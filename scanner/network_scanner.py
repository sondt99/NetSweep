import ipaddress
import time
import os
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from tabulate import tabulate
from tqdm import tqdm

from utils.system_utils import get_local_ip, get_local_mac
from scanner.device_info import DeviceInfo
from config import get_config

# Service names for the curated discovery port list (see NetworkScanner.discovery_ports).
# Looked up from a static map instead of socket.getservbyport(): that call is backed by a
# non-reentrant libc buffer and returns corrupted results when hit concurrently from many
# scanning threads at once.
DISCOVERY_PORT_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios', 143: 'imap',
    443: 'https', 465: 'smtps', 554: 'rtsp', 587: 'smtp-sub', 993: 'imaps',
    995: 'pop3s', 1723: 'pptp', 1883: 'mqtt', 3306: 'mysql', 3389: 'rdp',
    5432: 'postgresql', 5900: 'vnc', 8000: 'http-alt', 8080: 'http-alt',
    8443: 'https-alt', 8883: 'mqtt-ssl',
}


class NetworkScanner:
    def __init__(self, network, num_threads=50, scan_timeout=0.5, ip_timeout=2.0, output_dir="scan_results"):
        self.network = network
        self.num_threads = num_threads
        self.timeout = scan_timeout
        self.ip_timeout = ip_timeout  # Maximum time to spend scanning a single IP
        self.devices_found = 0
        self.start_time = None
        self.known_devices = self._load_known_devices()
        self.results = []
        self.local_ip = get_local_ip()
        self.device_info = DeviceInfo()
        self.skipped_ips = 0  # Track how many IPs were skipped due to timeout
        self.output_dir = output_dir

        # A /24 sweep classifies devices, it doesn't need a full 1-1000 port scan per
        # host - that's what the dedicated host_scanner.py is for. Use the curated
        # discovery port list so per-host scanning stays fast and fits ip_timeout.
        self.discovery_ports = get_config().network.common_ports_range

        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _load_known_devices(self):
        # Load known devices from a JSON file if it exists
        known_devices_file = "config/known_devices.json"
        default_devices = {
            '192.168.1.1': {'name': 'Router', 'type': 'network'},
            '192.168.1.254': {'name': 'Router', 'type': 'network'},
            '192.168.0.1': {'name': 'Router', 'type': 'network'}
        }
        
        if os.path.exists(known_devices_file):
            try:
                with open(known_devices_file, 'r') as f:
                    return json.load(f)
            except:
                return default_devices
        return default_devices

    def scan_ip(self, ip):
        try:
            # First check if the device is alive
            is_alive = self.device_info.check_device_alive(ip)

            if is_alive:
                # Small delay between IP scans
                time.sleep(0.1)

                mac = None
                if str(ip) == self.local_ip:
                    mac = get_local_mac()
                else:
                    # Try to get MAC address with limited retries
                    max_retries = 2
                    for attempt in range(max_retries):
                        mac = self.device_info.get_mac_address(str(ip))
                        if mac:
                            break
                        time.sleep(0.1)

                # Even if we can't get MAC, continue with port scanning
                vendor = self.device_info.get_vendor(mac) if mac else "N/A"

                # Scan a curated list of common ports for device classification (a full
                # 1-1000 sweep per host belongs to the dedicated host_scanner.py, not a
                # /24 discovery pass - see self.discovery_ports). Uses a single-thread
                # non-blocking scan rather than a per-host thread pool, since spinning up
                # one ThreadPoolExecutor per concurrently-scanned host multiplies with the
                # outer scan concurrency and starves the OS/GIL, causing false negatives.
                open_ports = self.device_info.scan_open_ports(str(ip), self.discovery_ports, self.timeout)

                # Convert ports to display strings
                port_strings = [f"{port}({DISCOVERY_PORT_SERVICES.get(port, 'unknown')})" for port in open_ports]

                # Determine device type based on open ports
                device_type = self._determine_device_type(port_strings)

                # Check if this is a known device
                device_name = "Unknown"
                if str(ip) in self.known_devices:
                    device_name = self.known_devices[str(ip)].get('name', 'Unknown')

                device_info = {
                    'ip': str(ip),
                    'mac': mac if mac else "N/A",
                    'vendor': vendor,
                    'ports': ', '.join(port_strings) if port_strings else "N/A",
                    'type': device_type,
                    'name': device_name,
                    'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                # Add to results even if MAC or ports are N/A
                return device_info
            else:
                # Device is not alive, return None
                return None

        except Exception as e:
            # All errors will be handled by the ThreadPoolExecutor timeout
            return None
    
    def _determine_device_type(self, open_ports):
        if not open_ports:
            return "Unknown"
            
        ports_str = ' '.join(open_ports)

        # Simple heuristics to determine device type.
        # RTSP/camera signature checked first: it's far more specific than "has 80+443",
        # which most devices with a web admin UI (including cameras themselves) also have.
        if '554(' in ports_str or '8000(' in ports_str:
            return "Camera/Media Device"

        if '80(' in ports_str and ('443(' in ports_str or '8443(' in ports_str):
            if '8080(' in ports_str or '8888(' in ports_str:
                return "Web Server"
            return "Web Device"

        if '22(' in ports_str and '3389(' not in ports_str:
            return "Linux/Unix Device"
            
        if '3389(' in ports_str:
            return "Windows Device"
            
        if '53(' in ports_str:
            return "DNS Server"
            
        if '25(' in ports_str or '587(' in ports_str or '465(' in ports_str:
            return "Mail Server"
            
        if '21(' in ports_str:
            return "FTP Server"

        if '1883(' in ports_str or '8883(' in ports_str:
            return "IoT Device"
            
        return "Generic Device"

    def scan(self, export_format=None):
        print("\nScanning network, please wait...")
        self.start_time = time.time()
        network = ipaddress.ip_network(self.network)
        total_hosts = sum(1 for _ in network.hosts())

        print(f"Network: {self.network}")
        print(f"Total hosts to scan: {total_hosts}")
        print(f"IP timeout limit: {self.ip_timeout}s per IP")
        print(f"Thread pool size: {self.num_threads}")

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            hosts = list(network.hosts())
            futures = [executor.submit(self.scan_ip, ip) for ip in hosts]

            with tqdm(total=total_hosts, desc="Scanning progress", unit="host") as pbar:
                for future in as_completed(futures):
                    try:
                        # Add timeout to the future.result() call
                        result = future.result(timeout=self.ip_timeout)  # Use exact IP timeout
                        if result and (result['mac'] != "N/A" or result['ports'] != "N/A"):
                            self.results.append(result)
                            self.devices_found += 1
                    except TimeoutError:
                        # Future timed out - this IP was too slow
                        self.skipped_ips += 1
                        print(f"\n⚠ IP scan timed out, skipping to next IP")
                        # Continue to next IP
                    except Exception as e:
                        # Other exceptions also continue to next IP
                        if "timeout" not in str(e).lower():
                            print(f"\nError during scan: {e}")
                        pass
                    finally:
                        pbar.update(1)

        self.results.sort(key=lambda x: list(map(int, x['ip'].split('.'))))
        
        headers = ['IP', 'MAC', 'Vendor', 'Device Type', 'Open Ports']
        table_data = [[
            r['ip'],
            r['mac'],
            r['vendor'],
            r['type'],
            r['ports']
        ] for r in self.results]
        
        print("\nScanning results:")
        print(tabulate(table_data, headers=headers, tablefmt='grid'))

        duration = time.time() - self.start_time
        print(f"\nStatistics:")
        print(f"- Scanning time: {duration:.2f} seconds")
        print(f"- Number of devices found: {self.devices_found}")
        print(f"- IPs skipped due to timeout: {self.skipped_ips}")
        if total_hosts > 0:
            timeout_rate = (self.skipped_ips / total_hosts) * 100
            print(f"- Timeout rate: {timeout_rate:.1f}%")
        
        # Export results if requested
        if export_format:
            self.export_results(export_format)
            
        return self.results
    
    def export_results(self, format_type):
        if not self.results:
            print("No devices found - skipping export.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_{timestamp}"

        if format_type.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"Results exported to {filename}.json")

        elif format_type.lower() == 'csv':
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
            print(f"Results exported to {filename}.csv")
            
        elif format_type.lower() == 'txt':
            headers = ['IP', 'MAC', 'Vendor', 'Device Type', 'Open Ports']
            table_data = [[
                r['ip'],
                r['mac'],
                r['vendor'],
                r['type'],
                r['ports']
            ] for r in self.results]
            
            with open(f"{filename}.txt", 'w') as f:
                f.write(tabulate(table_data, headers=headers, tablefmt='grid'))
            print(f"Results exported to {filename}.txt")
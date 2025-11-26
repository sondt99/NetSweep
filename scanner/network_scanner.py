import ipaddress
import time
import os
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from tqdm import tqdm

from utils.system_utils import get_local_ip, get_local_mac
from scanner.device_info import DeviceInfo
# Import the scan_ports function directly from host_scanner
# This provides the interface expected by NetworkScanner
import importlib.util
spec = importlib.util.spec_from_file_location("host_scanner", os.path.join(os.path.dirname(__file__), "..", "host_scanner.py"))
host_scanner_module = importlib.util.module_from_spec(spec)

try:
    spec.loader.exec_module(host_scanner_module)
    scan_ports = host_scanner_module.scan_ports
except:
    # Fallback if host_scanner is not available
    def scan_ports(ip, port_range, timeout, threads, verbose=False):
        return []

class NetworkScanner:
    def __init__(self, network, num_threads=50, scan_timeout=0.5, output_dir="scan_results"):
        self.network = network
        self.num_threads = num_threads
        self.timeout = scan_timeout
        self.devices_found = 0
        self.start_time = None
        self.known_devices = self._load_known_devices()
        self.results = []
        self.local_ip = get_local_ip()
        self.device_info = DeviceInfo()
        # Remove port_scanner as we'll use scan_ports function directly
        self.output_dir = output_dir
        
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
                # Reduced delay for faster scanning
                time.sleep(0.1)
                
                mac = None
                if str(ip) == self.local_ip:
                    mac = get_local_mac()
                else:
                    # Try to get MAC address
                    max_retries = 2
                    for attempt in range(max_retries):
                        mac = self.device_info.get_mac_address(str(ip))
                        if mac:
                            break
                        time.sleep(0.1)
                
                # Even if we can't get MAC, continue with port scanning
                vendor = self.device_info.get_vendor(mac) if mac else "N/A"
                
                # Scan for open ports
                open_ports = scan_ports(ip, "1-1000", self.timeout, 10)
                
                # Determine device type based on open ports
                device_type = self._determine_device_type(open_ports)
                
                # Check if this is a known device
                device_name = "Unknown"
                if str(ip) in self.known_devices:
                    device_name = self.known_devices[str(ip)].get('name', 'Unknown')
                
                device_info = {
                    'ip': str(ip),
                    'mac': mac if mac else "N/A",
                    'vendor': vendor,
                    'ports': ', '.join(open_ports) if open_ports else "N/A",
                    'type': device_type,
                    'name': device_name,
                    'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Add to results even if MAC or ports are N/A
                return device_info
                
        except Exception as e:
            print(f"Error when scanning {ip}: {str(e)}")
        return None
    
    def _determine_device_type(self, open_ports):
        if not open_ports:
            return "Unknown"
            
        ports_str = ' '.join(open_ports)
        
        # Simple heuristics to determine device type
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
            
        if '554(' in ports_str or '8000(' in ports_str:
            return "Camera/Media Device"
            
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
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            hosts = list(network.hosts())
            futures = [executor.submit(self.scan_ip, ip) for ip in hosts]
            
            with tqdm(total=total_hosts, desc="Scanning progress", unit="host") as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result and (result['mac'] != "N/A" or result['ports'] != "N/A"):
                            self.results.append(result)
                            self.devices_found += 1
                    except Exception:
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
        
        # Export results if requested
        if export_format:
            self.export_results(export_format)
            
        return self.results
    
    def export_results(self, format_type):
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
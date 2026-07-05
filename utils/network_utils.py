import ipaddress
import socket
import netifaces
import subprocess
import re
from typing import Dict, List

def get_local_networks() -> List[Dict[str, str]]:
    """Get all local networks with their interface names"""
    networks = []
    
    # Get interface friendly names mapping (Windows specific)
    interface_names = get_interface_friendly_names()
    
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        
        # Check if interface has IPv4 address
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr and 'netmask' in addr:
                    ip = addr['addr']
                    netmask = addr['netmask']
                    
                    # Skip loopback addresses for non-loopback interfaces
                    if ip.startswith('127.') and not interface.startswith('lo'):
                        continue
                    
                    # Calculate network in CIDR notation
                    try:
                        cidr = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        
                        # Use friendly name if available, otherwise use interface ID
                        friendly_name = interface_names.get(interface, interface)
                        
                        networks.append({
                            'interface': friendly_name,
                            'network': str(cidr)
                        })
                    except:
                        pass
    
    return networks

def get_interface_friendly_names() -> Dict[str, str]:
    """Get mapping between interface IDs and their friendly names (Windows)"""
    interface_names = {}
    
    try:
        # Run ipconfig /all command to get interface information
        output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
        
        # Parse the output to extract interface names and their descriptions
        sections = re.split(r'\r?\n\r?\n', output)
        current_interface = None
        
        for section in sections:
            # Look for adapter name
            adapter_match = re.search(r'(Ethernet adapter|Wireless LAN adapter|PPP adapter|VPN adapter|Bluetooth adapter|Tunnel adapter) (.*?):', section)
            if adapter_match:
                current_interface = adapter_match.group(2).strip()
            
            # Look for interface GUID
            guid_match = re.search(r'Physical Address.*?([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})', section, re.IGNORECASE)
            if guid_match and current_interface:
                mac = guid_match.group(1).replace('-', ':').lower()
                
                # Find the netifaces interface ID that matches this MAC
                for iface in netifaces.interfaces():
                    if netifaces.AF_LINK in netifaces.ifaddresses(iface):
                        for addr_info in netifaces.ifaddresses(iface)[netifaces.AF_LINK]:
                            if 'addr' in addr_info and addr_info['addr'].lower() == mac:
                                interface_names[iface] = current_interface
                                break
    except Exception as e:
        print(f"Warning: Could not get interface friendly names: {e}")
    
    return interface_names

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        # This creates a socket that doesn't actually connect to anything
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"  # Fallback to localhost
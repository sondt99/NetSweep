import ipaddress
import socket
import netifaces
import subprocess
import platform
import re
from typing import Dict, List, Optional

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


def _trace_route(target: str, max_hops: int) -> Optional[str]:
    """Run the platform's traceroute tool toward `target` and return its raw output.

    Tries `traceroute` first (present on most Linux/macOS boxes), falls back to
    `tracepath` (shipped in iputils, no root needed and available even where
    traceroute isn't - as on this project's own dev box), and uses `tracert` on
    Windows. Returns None if none of them are installed or the probe errors out.
    """
    is_windows = platform.system().lower() == "windows"

    if is_windows:
        candidates = [["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]]
    else:
        # -n: no reverse DNS (faster). traceroute: -q 1 = one probe/hop, -w 1 = 1s wait.
        candidates = [
            ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), target],
            ["tracepath", "-n", "-m", str(max_hops), target],
        ]

    # Give the probe enough wall-clock for max_hops sequential 1s waits, plus slack.
    overall_timeout = max_hops * 2 + 5

    for command in candidates:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=overall_timeout,
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            if output.strip():
                return output
        except FileNotFoundError:
            continue  # Tool not installed - try the next candidate
        except subprocess.SubprocessError:
            continue  # Timed out or otherwise failed - try the next candidate

    return None


def get_upstream_networks(max_hops: int = 8, probe_target: str = "8.8.8.8") -> List[Dict[str, str]]:
    """Discover reachable upstream networks by tracing the route toward the internet.

    A NAT'd host only has its own LAN bound to an interface, so get_local_networks()
    can't see the routers sitting *above* the gateway - e.g. a landlord's shared
    network in a building where every room has its own router. Those upstream
    networks are usually still reachable (and scannable) through the gateway.

    This traces the first few hops toward an internet target, keeps the private-range
    hops, and derives a /24 network for each. Networks already bound locally are
    excluded so the result is exactly the "extra" networks a normal interface scan
    would miss. Returns a list of {'network': '<cidr>', 'via': '<hop-ip>'} dicts,
    or an empty list if no traceroute tool is available or no upstream hop is found.
    """
    output = _trace_route(probe_target, max_hops)
    if not output:
        return []

    # Networks already attached to an interface - exclude these from the results,
    # since the interface list already covers them.
    local_networks = []
    for net in get_local_networks():
        try:
            local_networks.append(ipaddress.ip_network(net["network"], strict=False))
        except ValueError:
            continue

    upstream: List[Dict[str, str]] = []
    seen_networks = set()

    # Pull every IPv4 address out of the traceroute output, in hop order.
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for hop in ip_pattern.findall(output):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            continue

        # Only private, routable-LAN hops are interesting: skip public internet
        # hops, loopback, and link-local (169.254.x) addresses.
        if not addr.is_private or addr.is_loopback or addr.is_link_local:
            continue

        network = ipaddress.ip_network(f"{hop}/24", strict=False)

        if network in seen_networks:
            continue
        if any(addr in local_net for local_net in local_networks):
            continue

        seen_networks.add(network)
        upstream.append({"network": str(network), "via": hop})

    return upstream
"""Network interface helpers for NetSweep."""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional

import netifaces


def get_local_ip() -> Optional[str]:
    """Return the local IPv4 used for outbound traffic, or None on failure."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def get_local_ip_str() -> str:
    """Return local IPv4 or \"127.0.0.1\" fallback (string contract for callers that need it)."""
    return get_local_ip() or "127.0.0.1"


def get_local_mac() -> Optional[str]:
    """Get the MAC address of the first non-loopback interface, or None on failure."""
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get("addr")
                if mac and mac != "00:00:00:00:00:00":
                    return mac.upper()
    except Exception as e:
        print(f"Error when getting local MAC: {str(e)}")
    return None


def get_interface_friendly_names() -> Dict[str, str]:
    """Map interface IDs to friendly names (Windows only)."""
    interface_names: Dict[str, str] = {}
    if platform.system().lower() != "windows":
        return interface_names
    try:
        output = subprocess.check_output(
            ["ipconfig", "/all"], shell=False
        ).decode("utf-8", errors="ignore")
        sections = re.split(r"\r?\n\r?\n", output)
        current_interface = None
        for section in sections:
            adapter_match = re.search(
                r"(Ethernet adapter|Wireless LAN adapter|PPP adapter|VPN adapter|"
                r"Bluetooth adapter|Tunnel adapter) (.*?):",
                section,
            )
            if adapter_match:
                current_interface = adapter_match.group(2).strip()
            guid_match = re.search(
                r"Physical Address.*?([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-"
                r"[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})",
                section,
                re.IGNORECASE,
            )
            if guid_match and current_interface:
                mac = guid_match.group(1).replace("-", ":").lower()
                for iface in netifaces.interfaces():
                    if netifaces.AF_LINK in netifaces.ifaddresses(iface):
                        for addr_info in netifaces.ifaddresses(iface)[netifaces.AF_LINK]:
                            if "addr" in addr_info and addr_info["addr"].lower() == mac:
                                interface_names[iface] = current_interface
                                break
    except Exception as e:
        print(f"Warning: Could not get interface friendly names: {e}")
    return interface_names


def get_local_networks() -> List[Dict[str, str]]:
    """Return local IPv4 networks with interface names."""
    networks: List[Dict[str, str]] = []
    interface_names = get_interface_friendly_names()
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addrs:
            continue
        for addr in addrs[netifaces.AF_INET]:
            if "addr" not in addr or "netmask" not in addr:
                continue
            ip = addr["addr"]
            netmask = addr["netmask"]
            if ip.startswith("127.") and not interface.startswith("lo"):
                continue
            try:
                cidr = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                friendly_name = interface_names.get(interface, interface)
                networks.append({"interface": friendly_name, "network": str(cidr)})
            except (ValueError, TypeError):
                pass
    return networks


def _trace_route(target: str, max_hops: int) -> Optional[str]:
    """Run platform traceroute and return raw output."""
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        candidates = [["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]]
    else:
        candidates = [
            ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), target],
            ["tracepath", "-n", "-m", str(max_hops), target],
        ]
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
            continue
        except subprocess.SubprocessError:
            continue
    return None


def get_upstream_networks(max_hops: int = 8, probe_target: str = "8.8.8.8") -> List[Dict[str, str]]:
    """Discover private upstream networks via traceroute (authorized use only)."""
    output = _trace_route(probe_target, max_hops)
    if not output:
        return []
    local_networks = []
    for net in get_local_networks():
        try:
            local_networks.append(ipaddress.ip_network(net["network"], strict=False))
        except ValueError:
            continue
    upstream: List[Dict[str, str]] = []
    seen_networks = set()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for hop in ip_pattern.findall(output):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            continue
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

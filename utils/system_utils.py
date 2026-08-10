import socket
import netifaces
from typing import Optional

def get_local_ip() -> Optional[str]:
    """Get the local IPv4 address used for outbound traffic, or None on failure."""
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

def get_local_mac() -> Optional[str]:
    """Get the MAC address of the first non-loopback interface, or None on failure."""
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0]['addr']
                if mac and mac != "00:00:00:00:00:00":
                    return mac.upper()
    except Exception as e:
        print(f"Error when getting local MAC: {str(e)}")
    return None
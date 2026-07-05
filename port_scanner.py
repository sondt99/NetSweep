#!/usr/bin/env python3
"""
Advanced port scanner module for Host Scanner Network
"""

import socket
import random
import concurrent.futures
from typing import Dict, Iterable, List, Tuple
from scapy.all import sr1, IP, TCP, ICMP

class PortScanner:
    """Multi-technique TCP/UDP port scanner (connect, SYN, UDP)."""

    def __init__(self, target: str, timeout: float = 1.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports: List[int] = []
        self.filtered_ports: List[int] = []
        self.closed_ports: List[int] = []

    def tcp_connect_scan(self, ports: Iterable[int], threads: int = 100) -> None:
        """Standard TCP connect scan"""
        if self.verbose:
            print("[*] Performing TCP Connect scan...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self._tcp_connect_scan_port, port): port for port in ports}

            for future in concurrent.futures.as_completed(future_to_port):
                port, status = future.result()
                if status == "open":
                    self.open_ports.append(port)
                elif status == "filtered":
                    self.filtered_ports.append(port)
                else:
                    self.closed_ports.append(port)

    def _tcp_connect_scan_port(self, port: int) -> Tuple[int, str]:
        """Scan a single port using TCP connect"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                if self.verbose:
                    print(f"[+] Port {port}/tcp is open")
                return port, "open"
            elif result == 111:  # Connection refused
                return port, "closed"
            else:
                return port, "filtered"
        except socket.timeout:
            return port, "filtered"
        except:
            return port, "filtered"
    
    def syn_scan(self, ports: Iterable[int], threads: int = 50) -> None:
        """SYN scan using scapy (requires root/admin privileges)"""
        if self.verbose:
            print("[*] Performing SYN scan (requires admin/root privileges)...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self._syn_scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, status = future.result()
                if status == "open":
                    self.open_ports.append(port)
                elif status == "filtered":
                    self.filtered_ports.append(port)
                else:
                    self.closed_ports.append(port)
    
    def _syn_scan_port(self, port: int) -> Tuple[int, str]:
        """Scan a single port using SYN scan"""
        try:
            # Send SYN packet
            src_port = random.randint(1025, 65534)
            resp = sr1(IP(dst=self.target)/TCP(sport=src_port, dport=port, flags="S"), timeout=self.timeout, verbose=0)
            
            if resp is None:
                return port, "filtered"
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    sr1(IP(dst=self.target)/TCP(sport=src_port, dport=port, flags="R"), timeout=self.timeout, verbose=0)
                    if self.verbose:
                        print(f"[+] Port {port}/tcp is open")
                    return port, "open"
                elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return port, "closed"
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    return port, "filtered"
            
            return port, "filtered"
        except Exception as e:
            if self.verbose:
                print(f"[-] Error scanning port {port}: {e}")
            return port, "filtered"
    
    def udp_scan(self, ports: Iterable[int], threads: int = 50) -> None:
        """UDP scan (requires root/admin privileges)"""
        if self.verbose:
            print("[*] Performing UDP scan (requires admin/root privileges)...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self._udp_scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port, status = future.result()
                if status == "open|filtered":
                    self.open_ports.append(port)
                elif status == "filtered":
                    self.filtered_ports.append(port)
                else:
                    self.closed_ports.append(port)
    
    def _udp_scan_port(self, port: int) -> Tuple[int, str]:
        """Scan a single port using UDP scan"""
        try:
            # Create UDP packet
            resp = sr1(IP(dst=self.target)/UDP(dport=port), timeout=self.timeout, verbose=0)
            
            if resp is None:
                return port, "open|filtered"
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3:
                    return port, "closed"
                elif int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    return port, "filtered"
            else:
                if self.verbose:
                    print(f"[+] Port {port}/udp is open")
                return port, "open"
            
            return port, "filtered"
        except Exception as e:
            if self.verbose:
                print(f"[-] Error scanning port {port}: {e}")
            return port, "filtered"
    
    def get_results(self) -> Dict[str, List[int]]:
        """Return scan results"""
        return {
            "open": sorted(list(set(self.open_ports))),
            "filtered": sorted(list(set(self.filtered_ports))),
            "closed": sorted(list(set(self.closed_ports)))
        }
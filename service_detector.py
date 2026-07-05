#!/usr/bin/env python3
"""
Service detection module for Host Scanner Network
"""

import socket
import re
import ssl
import time
import json
import os
from typing import Any, Dict, List, Optional, Tuple

class ServiceDetector:
    """Detects the service, version, and (for SSL ports) certificate running on a port."""

    def __init__(self, target: str, timeout: float = 2.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.service_probes = {
            "HTTP": b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HostScanner/1.0\r\nAccept: */*\r\n\r\n",
            "HTTPS": b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HostScanner/1.0\r\nAccept: */*\r\n\r\n",
            "FTP": b"",  # FTP servers send banner automatically
            "SSH": b"",  # SSH servers send banner automatically
            "SMTP": b"",  # SMTP servers send banner automatically
            "POP3": b"",  # POP3 servers send banner automatically
            "IMAP": b"",  # IMAP servers send banner automatically
            "TELNET": b"",  # TELNET servers send banner automatically
            "DNS": b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS query
            "MYSQL": b"\x20\x00\x00\x00\x03\x73\x65\x6c\x65\x63\x74\x20\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x20\x6c\x69\x6d\x69\x74\x20\x31",  # MySQL query
            "MSSQL": b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00",  # MSSQL query
            "REDIS": b"INFO\r\n",  # Redis INFO command
            "MONGODB": b"\x3a\x00\x00\x00\x9b\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01\x73\x65\x72\x76\x65\x72\x53\x74\x61\x74\x75\x73\x00\x00\x00\x00\x00\x00\x00\xf0\x3f\x00",  # MongoDB serverStatus
            "GENERIC": b"\r\n\r\n"  # Generic probe
        }
        
        self.service_patterns = {
            "HTTP": re.compile(r"^HTTP/\d\.\d (\d+).*$", re.IGNORECASE | re.MULTILINE),
            "SSH": re.compile(r"^SSH-(\d+\.\d+)-(.*)$", re.IGNORECASE | re.MULTILINE),
            "FTP": re.compile(r"^220[ -](.*)$", re.IGNORECASE | re.MULTILINE),
            "SMTP": re.compile(r"^220[ -](.*)$", re.IGNORECASE | re.MULTILINE),
            "POP3": re.compile(r"^\+OK (.*)$", re.IGNORECASE | re.MULTILINE),
            "IMAP": re.compile(r"^\* OK (.*)$", re.IGNORECASE | re.MULTILINE),
            "TELNET": re.compile(r"^.*[Tt][Ee][Ll][Nn][Ee][Tt].*$", re.IGNORECASE | re.MULTILINE),
            "MYSQL": re.compile(r"^.\x00\x00\x00\x0a([\d\.]+).*$", re.MULTILINE | re.DOTALL),
            "MSSQL": re.compile(r"^.\x00\x00\x00\x04.*[Mm][Ii][Cc][Rr][Oo][Ss][Oo][Ff][Tt].*$", re.MULTILINE | re.DOTALL),
            "REDIS": re.compile(r"^.*redis_version:([\d\.]+).*$", re.IGNORECASE | re.MULTILINE | re.DOTALL),
            "MONGODB": re.compile(r"^.*version.*$", re.IGNORECASE | re.MULTILINE | re.DOTALL)
        }
    
    def detect_service(self, port: int) -> Dict[str, Any]:
        """Detect service on a specific port"""
        if self.verbose:
            print(f"[*] Detecting service on port {port}...")
        
        # Try common services based on port number
        service_name = self._get_common_service(port)
        
        # Try to connect and get banner
        banner = None
        version = None
        
        # Try SSL first for common SSL ports
        if port in [443, 465, 636, 993, 995, 8443]:
            ssl_banner = self._get_ssl_banner(port)
            if ssl_banner:
                banner = ssl_banner
                service_name, version = self._identify_service_from_banner(banner, service_name, port, ssl=True)
        
        # If no SSL banner or not an SSL port, try regular connection
        if not banner:
            banner = self._get_banner(port, service_name)
            if banner:
                service_name, version = self._identify_service_from_banner(banner, service_name, port)
        
        # Get SSL certificate info if it's an SSL service
        cert_info = None
        if service_name in ["https", "imaps", "pop3s", "smtps", "ldaps"] or port in [443, 465, 636, 993, 995, 8443]:
            cert_info = self._get_ssl_cert_info(port)
        
        return {
            "port": port,
            "service": service_name,
            "version": version,
            "banner": banner,
            "ssl_cert": cert_info
        }
    
    def _get_common_service(self, port: int) -> str:
        """Get common service name based on port number"""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            465: "smtps",
            587: "smtp",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb"
        }
        
        return common_ports.get(port, "unknown")
    
    def _get_banner(self, port: int, service_name: str) -> Optional[str]:
        """Get service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Send appropriate probe based on service. Alt-HTTP(S) port names like
            # "http-proxy" (8080) or "https-alt" (8443) don't have their own probe
            # dict entry, so route anything starting with http(s) to the HTTP(S)
            # probe instead of silently falling through to the generic one below.
            probe_key = service_name.upper()
            if probe_key.startswith("HTTPS"):
                probe_key = "HTTPS"
            elif probe_key.startswith("HTTP"):
                probe_key = "HTTP"

            if probe_key in self.service_probes:
                probe_template = self.service_probes[probe_key]
                # Only HTTP/HTTPS probes contain a "%s" placeholder for the host;
                # every other probe is a literal (often binary) payload, and
                # applying bytes "%" formatting to one without a placeholder
                # raises "not all arguments converted during bytes formatting".
                if b"%s" in probe_template:
                    probe = probe_template % self.target.encode()
                else:
                    probe = probe_template
                if probe:  # Only send if probe is not empty
                    sock.send(probe)
            else:
                # Try generic probe
                sock.send(self.service_probes["GENERIC"])
            
            # Wait a moment for response
            time.sleep(0.5)
            
            # Receive response
            banner = b""
            sock.settimeout(1)
            
            try:
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    banner += data
            except socket.timeout:
                pass
            
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore')
            return None
        except Exception as e:
            if self.verbose:
                print(f"[-] Error getting banner on port {port}: {e}")
            return None
    
    def _get_ssl_banner(self, port: int) -> Optional[str]:
        """Get banner using SSL connection"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            
            # Send HTTP probe for HTTPS ports
            if port in [443, 8443]:
                ssl_sock.send(self.service_probes["HTTPS"] % self.target.encode())
            
            # Wait a moment for response
            time.sleep(0.5)
            
            # Receive response
            banner = b""
            ssl_sock.settimeout(1)
            
            try:
                while True:
                    data = ssl_sock.recv(1024)
                    if not data:
                        break
                    banner += data
            except socket.timeout:
                pass
            
            ssl_sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore')
            return None
        except Exception as e:
            if self.verbose:
                print(f"[-] Error getting SSL banner on port {port}: {e}")
            return None
    
    @staticmethod
    def _extract_cert_names(rdns: Any) -> Dict[str, str]:
        """Extract CN/O/OU short names from an x509 subject or issuer RDN sequence."""
        names = {}
        for item in rdns:
            for key, value in item:
                if key == "commonName":
                    names["CN"] = value
                elif key == "organizationName":
                    names["O"] = value
                elif key == "organizationalUnitName":
                    names["OU"] = value
        return names

    def _get_ssl_cert_info(self, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssl_sock:
                    cert = ssl_sock.getpeercert(binary_form=False)

                    if not cert:
                        return None

                    cert_info = {
                        "subject": {},
                        "issuer": {},
                        "version": cert.get("version", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", "")
                    }

                    if "subject" in cert:
                        cert_info["subject"] = self._extract_cert_names(cert["subject"])

                    if "issuer" in cert:
                        cert_info["issuer"] = self._extract_cert_names(cert["issuer"])

                    return cert_info
        except Exception as e:
            if self.verbose:
                print(f"[-] Error getting SSL certificate on port {port}: {e}")
            return None

    def _identify_service_from_banner(self, banner: str, service_name: str, port: int, ssl: bool = False) -> Tuple[str, str]:
        """Identify service and version from banner"""
        version = "unknown"
        
        # Check for HTTP
        if re.search(self.service_patterns["HTTP"], banner):
            service_name = "https" if ssl else "http"
            
            # Try to identify web server
            if "Server:" in banner:
                server_line = re.search(r"Server: ([^\r\n]+)", banner)
                if server_line:
                    version = server_line.group(1)
            elif "X-Powered-By:" in banner:
                powered_line = re.search(r"X-Powered-By: ([^\r\n]+)", banner)
                if powered_line:
                    version = powered_line.group(1)
        
        # Check for SSH
        elif re.search(self.service_patterns["SSH"], banner):
            service_name = "ssh"
            ssh_match = re.search(self.service_patterns["SSH"], banner)
            if ssh_match:
                version = f"SSH-{ssh_match.group(1)}-{ssh_match.group(2)}"
        
        # Check for FTP
        elif re.search(self.service_patterns["FTP"], banner):
            service_name = "ftp"
            ftp_match = re.search(self.service_patterns["FTP"], banner)
            if ftp_match:
                version = ftp_match.group(1)
        
        # Check for SMTP
        elif re.search(self.service_patterns["SMTP"], banner):
            service_name = "smtp" if not ssl else "smtps"
            smtp_match = re.search(self.service_patterns["SMTP"], banner)
            if smtp_match:
                version = smtp_match.group(1)
        
        # Check for POP3
        elif re.search(self.service_patterns["POP3"], banner):
            service_name = "pop3" if not ssl else "pop3s"
            pop3_match = re.search(self.service_patterns["POP3"], banner)
            if pop3_match:
                version = pop3_match.group(1)
        
        # Check for IMAP
        elif re.search(self.service_patterns["IMAP"], banner):
            service_name = "imap" if not ssl else "imaps"
            imap_match = re.search(self.service_patterns["IMAP"], banner)
            if imap_match:
                version = imap_match.group(1)
        
        # Check for TELNET
        elif re.search(self.service_patterns["TELNET"], banner):
            service_name = "telnet"
            # Telnet doesn't typically provide version info in a standard format
        
        # Check for MySQL
        elif re.search(self.service_patterns["MYSQL"], banner):
            service_name = "mysql"
            mysql_match = re.search(self.service_patterns["MYSQL"], banner)
            if mysql_match:
                version = mysql_match.group(1)
        
        # Check for MSSQL
        elif re.search(self.service_patterns["MSSQL"], banner):
            service_name = "mssql"
            # Extract version from complex binary format if possible
        
        # Check for Redis
        elif re.search(self.service_patterns["REDIS"], banner):
            service_name = "redis"
            redis_match = re.search(self.service_patterns["REDIS"], banner)
            if redis_match:
                version = redis_match.group(1)
        
        # Check for MongoDB
        elif re.search(self.service_patterns["MONGODB"], banner):
            service_name = "mongodb"
            # Extract version if available in the response
        
        # If we couldn't identify the service but have a banner, try generic identification
        elif banner:
            # Look for common strings in the banner
            if "nginx" in banner.lower():
                service_name = "http"
                nginx_ver = re.search(r"nginx/(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
                if nginx_ver:
                    version = f"nginx/{nginx_ver.group(1)}"
            elif "apache" in banner.lower():
                service_name = "http"
                apache_ver = re.search(r"apache/(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
                if apache_ver:
                    version = f"Apache/{apache_ver.group(1)}"
            elif "openssl" in banner.lower():
                openssl_ver = re.search(r"openssl/(\d+\.\d+\.\d+)", banner, re.IGNORECASE)
                if openssl_ver:
                    version = f"OpenSSL/{openssl_ver.group(1)}"
        
        return service_name, version

    def scan_services(self, ports: List[int], auto_export: bool = True, output_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan multiple ports for services
        
        Args:
            ports: List of ports to scan
            auto_export: Whether to automatically export results to JSON (default: True)
            output_file: Path to output file (default: target_scan_results.json)
            
        Returns:
            List of service detection results
        """
        results = []
        
        for port in ports:
            if self.verbose:
                print(f"[*] Scanning port {port} for services...")
            
            service_info = self.detect_service(port)
            results.append(service_info)
            
            if self.verbose:
                print(f"[+] Port {port}: {service_info['service']} - {service_info['version']}")
                if service_info['banner']:
                    print(f"    Banner: {service_info['banner'].strip()[:100]}...")
                if service_info['ssl_cert']:
                    print(f"    SSL Certificate: Subject CN={service_info['ssl_cert']['subject'].get('CN', 'N/A')}")
        
        # Automatically export results to JSON if enabled
        if auto_export:
            json_file = self.export_to_json(results, output_file)
            if self.verbose:
                print(f"\n[+] Scan results automatically exported to: {json_file}")
        
        return results

    def export_to_json(self, results: List[Dict[str, Any]], output_file: Optional[str] = None) -> str:
        """Export scan results to a JSON file
        
        Args:
            results: List of service detection results
            output_file: Path to output file (default: target_scan_results.json)
        
        Returns:
            Path to the output file
        """
        # Create results directory if it doesn't exist
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        # Create IP-specific directory
        ip_dir = os.path.join(results_dir, self.target)
        if not os.path.exists(ip_dir):
            os.makedirs(ip_dir)
        
        # Generate timestamp for filename
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        
        if output_file is None:
            # Create filename with IP and timestamp
            output_file = os.path.join(ip_dir, f"{self.target}_{timestamp}.json")
        else:
            # If output_file is provided but doesn't include the IP directory
            if not output_file.startswith(ip_dir):
                output_file = os.path.join(ip_dir, os.path.basename(output_file))
        
        # Create a structured output
        output_data = {
            "target": self.target,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ports_scanned": len(results),
            "open_ports": [result for result in results if result["service"] != "unknown"],
            "scan_results": results
        }
        
        # Write to file with nice formatting
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=4)
        
        if self.verbose:
            print(f"[+] Results exported to {output_file}")
        
        return output_file
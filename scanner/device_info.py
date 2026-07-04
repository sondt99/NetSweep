import subprocess
import socket
import select
import requests
import logging
import time
from getmac import get_mac_address
import platform

class DeviceInfo:
    def __init__(self):
        self.vendor_cache = {}
        self.mac_cache = {}
        self.timeout = 0.5
        logging.basicConfig(level=logging.INFO)

    def check_device_alive(self, ip):
        try:
            # Probe common ports concurrently (non-blocking connect + select) instead of
            # one-by-one, so the whole probe costs ~self.timeout instead of N * self.timeout
            if self._check_ports_concurrent(str(ip)):
                return True

            # Fall back to ICMP ping
            if self._ping(str(ip)):
                return True

            # Last resort: check the OS ARP/neighbor table (works on Linux/macOS too, not just Windows)
            if self._check_arp(str(ip)):
                return True

            return False
        except Exception as e:
            logging.error(f"Error checking if device is alive: {e}")
            return False

    def _check_ports_concurrent(self, ip):
        """Try connecting to several common ports at once; return True on first success."""
        common_ports = [80, 443, 22, 8080, 53, 3389, 445, 139, 21, 23, 5000]
        sockets = {}
        try:
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                try:
                    sock.connect_ex((ip, port))
                    sockets[sock] = port
                except OSError:
                    sock.close()

            deadline = time.time() + self.timeout
            pending = list(sockets.keys())
            while pending:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                _, writable, _ = select.select([], pending, [], remaining)
                if not writable:
                    break
                for sock in writable:
                    pending.remove(sock)
                    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        return True
            return False
        finally:
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass

    def _ping(self, ip):
        try:
            is_windows = platform.system().lower() == "windows"
            param = "-n" if is_windows else "-c"
            timeout_param = "-w" if is_windows else "-W"
            timeout_value = str(int(self.timeout * 1000)) if is_windows else str(max(1, int(self.timeout)))

            command = ["ping", param, "1", timeout_param, timeout_value, ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout + 1)
            return result.returncode == 0
        except Exception:
            return False

    def scan_open_ports(self, ip, ports, timeout=None):
        """Concurrently probe a list of ports on ip via non-blocking connect + select,
        returning the sorted list of ports that are open. Unlike spinning up a
        ThreadPoolExecutor per host, this uses a single thread regardless of how many
        ports/hosts are scanned at once, so it stays correct when many hosts are being
        scanned in parallel (a per-host thread pool multiplies with outer scan
        concurrency and starves the OS/GIL, causing false negatives under load)."""
        timeout = self.timeout if timeout is None else timeout
        sockets = {}
        open_ports = []
        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                try:
                    sock.connect_ex((ip, port))
                    sockets[sock] = port
                except OSError:
                    sock.close()

            deadline = time.time() + timeout
            pending = list(sockets.keys())
            while pending:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                _, writable, _ = select.select([], pending, [], remaining)
                if not writable:
                    break
                for sock in writable:
                    pending.remove(sock)
                    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        open_ports.append(sockets[sock])
            return sorted(open_ports)
        finally:
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass

    def _check_arp(self, ip):
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
                output = result.stdout.decode('utf-8', errors='ignore')
                return ip in output and "ff-ff-ff-ff-ff-ff" not in output.lower()

            # Linux/macOS: prefer `ip neigh`, fall back to `arp -n`
            try:
                result = subprocess.run(["ip", "neigh", "show", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
                output = result.stdout.decode('utf-8', errors='ignore')
                if output and "incomplete" not in output.lower() and "failed" not in output.lower():
                    return True
            except (FileNotFoundError, subprocess.SubprocessError):
                pass

            result = subprocess.run(["arp", "-n", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
            output = result.stdout.decode('utf-8', errors='ignore')
            return ip in output and "no match found" not in output.lower() and "(incomplete)" not in output.lower()
        except Exception:
            return False

    def get_mac_address(self, ip):
        if ip in self.mac_cache:
            return self.mac_cache[ip]

        try:
            mac = get_mac_address(ip=str(ip))
            if mac:
                self.mac_cache[ip] = mac
                return mac
        except Exception as e:
            logging.error(f"Error when getting MAC for {ip}: {str(e)}")
        return None

    def get_vendor(self, mac_address):
        if not mac_address or mac_address == "N/A":
            return "N/A"

        try:
            oui = mac_address.replace(':', '').replace('-', '').upper()[:6]

            # Locally-administered MACs (2nd LSB of the first octet set) are randomized
            # privacy addresses (common on modern phones/laptops) and will never match a
            # real vendor OUI - skip the API call entirely instead of burning retries on it.
            if len(oui) == 6 and int(oui[0:2], 16) & 0x02:
                return "Randomized/Private MAC"

            if oui in self.vendor_cache:
                return self.vendor_cache[oui]

            url = f"https://api.macvendors.com/{oui}"

            max_retries = 3
            retry_delay = 1.0

            for attempt in range(max_retries):
                try:
                    response = requests.get(url, timeout=2)

                    if response.status_code == 200:
                        vendor = response.text
                        self.vendor_cache[oui] = vendor
                        return vendor
                    elif response.status_code == 429:
                        # Only rate-limiting is worth retrying
                        time.sleep(retry_delay)
                        retry_delay = min(retry_delay * 2, 5)
                        continue
                    else:
                        # e.g. 404 "OUI not found" - this is a definitive answer, retrying won't help
                        self.vendor_cache[oui] = "Unknown"
                        return "Unknown"
                except requests.exceptions.RequestException as e:
                    logging.error(f"Connection API error (attempt {attempt + 1}): {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue

            logging.warning(f"Exceeded retry limit for MAC {mac_address}")
            self.vendor_cache[oui] = "Unknown"
            return "Unknown"

        except Exception as e:
            logging.error(f"Unexpected error when getting vendor for MAC {mac_address}: {str(e)}")
            return "Unknown"
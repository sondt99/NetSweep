import subprocess
import socket
import select
import selectors
import logging
import re
import time
import threading
from typing import Dict, List, Optional

import requests
from getmac import get_mac_address
import platform

from utils.connection_budget import get_connection_semaphore
from utils.oui_db import lookup_oui_offline
from config import get_config

logger = logging.getLogger(__name__)


class DeviceInfo:
    """Host-liveness, port, MAC, and vendor lookups used by the LAN scanner."""

    def __init__(self, timeout: Optional[float] = None):
        self.vendor_cache: Dict[str, str] = {}
        self.mac_cache: Dict[str, str] = {}
        self._cache_lock = threading.Lock()
        self.timeout = timeout if timeout is not None else 0.5

    def check_device_alive(self, ip) -> bool:
        try:
            if self._check_ports_concurrent(str(ip)):
                return True
            if self._ping(str(ip)):
                return True
            if self._check_arp(str(ip)):
                return True
            return False
        except Exception as e:
            logger.error("Error checking if device is alive: %s", e)
            return False

    def _check_ports_concurrent(self, ip: str) -> bool:
        """Try connecting to several common ports at once; return True on first success."""
        common_ports = [80, 443, 22, 8080, 53, 3389, 445, 139, 21, 23, 5000]
        sockets = {}
        sem = get_connection_semaphore()
        acquired = 0
        try:
            for port in common_ports:
                if not sem.acquire(blocking=True, timeout=self.timeout + 0.5):
                    break
                acquired += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                try:
                    sock.connect_ex((ip, port))
                    sockets[sock] = port
                except OSError:
                    sock.close()
                    sem.release()
                    acquired -= 1

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
            for _ in range(acquired):
                try:
                    sem.release()
                except ValueError:
                    break

    def _ping(self, ip: str) -> bool:
        try:
            is_windows = platform.system().lower() == "windows"
            param = "-n" if is_windows else "-c"
            timeout_param = "-w" if is_windows else "-W"
            timeout_value = str(int(self.timeout * 1000)) if is_windows else str(max(1, int(self.timeout)))

            command = ["ping", param, "1", timeout_param, timeout_value, ip]
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 1,
                shell=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan_open_ports(self, ip: str, ports: List[int], timeout: Optional[float] = None) -> List[int]:
        """Probe ports with a selector, under a process-wide connection budget.

        Ports are processed in batches so hosts×ports cannot exhaust FDs.
        """
        timeout = self.timeout if timeout is None else timeout
        open_ports: List[int] = []
        sem = get_connection_semaphore()
        batch_size = min(64, max(8, get_config().security.max_concurrent_connections // max(1, 4)))

        for offset in range(0, len(ports), batch_size):
            batch = ports[offset : offset + batch_size]
            sockets = {}
            acquired = 0
            sel = selectors.DefaultSelector()
            try:
                for port in batch:
                    if not sem.acquire(blocking=True, timeout=timeout + 1.0):
                        break
                    acquired += 1
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    try:
                        sock.connect_ex((ip, port))
                        sockets[sock] = port
                        sel.register(sock, selectors.EVENT_WRITE)
                    except OSError:
                        sock.close()
                        sem.release()
                        acquired -= 1

                deadline = time.time() + timeout
                pending = len(sockets)
                while pending:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    events = sel.select(timeout=remaining)
                    if not events:
                        break
                    for key, _ in events:
                        sock = key.fileobj
                        try:
                            sel.unregister(sock)
                        except Exception:
                            pass
                        pending -= 1
                        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                            open_ports.append(sockets[sock])
            finally:
                try:
                    sel.close()
                except Exception:
                    pass
                for sock in sockets:
                    try:
                        sock.close()
                    except OSError:
                        pass
                for _ in range(acquired):
                    try:
                        sem.release()
                    except ValueError:
                        break

        return sorted(open_ports)

    _MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")

    def _check_arp(self, ip: str) -> bool:
        """Return True only when the OS ARP/neighbor table holds a resolved MAC for ip."""

        def _has_real_mac(text: str) -> bool:
            match = self._MAC_RE.search(text.replace("-", ":"))
            return bool(match) and match.group(0).lower() != "ff:ff:ff:ff:ff:ff"

        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["arp", "-a", ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1,
                    shell=False,
                )
                return _has_real_mac(result.stdout.decode("utf-8", errors="ignore"))

            try:
                result = subprocess.run(
                    ["ip", "neigh", "show", ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=1,
                    shell=False,
                )
                output = result.stdout.decode("utf-8", errors="ignore")
                lowered = output.lower()
                if "failed" not in lowered and "incomplete" not in lowered and _has_real_mac(output):
                    return True
            except (FileNotFoundError, subprocess.SubprocessError):
                pass

            result = subprocess.run(
                ["arp", "-n", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=1,
                shell=False,
            )
            return _has_real_mac(result.stdout.decode("utf-8", errors="ignore"))
        except Exception:
            return False

    def get_mac_address(self, ip: str) -> Optional[str]:
        with self._cache_lock:
            if ip in self.mac_cache:
                return self.mac_cache[ip]

        try:
            mac = get_mac_address(ip=str(ip))
            if mac:
                with self._cache_lock:
                    self.mac_cache[ip] = mac
                return mac
        except Exception as e:
            logger.error("Error when getting MAC for %s: %s", ip, e)
        return None

    def get_vendor(self, mac_address: Optional[str], allow_online: Optional[bool] = None) -> str:
        if not mac_address or mac_address == "N/A":
            return "N/A"

        try:
            oui = mac_address.replace(":", "").replace("-", "").upper()[:6]

            if len(oui) == 6 and int(oui[0:2], 16) & 0x02:
                return "Randomized/Private MAC"

            with self._cache_lock:
                if oui in self.vendor_cache:
                    return self.vendor_cache[oui]

            offline = lookup_oui_offline(mac_address)
            if offline:
                with self._cache_lock:
                    self.vendor_cache[oui] = offline
                return offline

            cfg = get_config()
            online_enabled = (
                allow_online
                if allow_online is not None
                else getattr(cfg.security, "online_vendor_lookup", False)
            )
            if not online_enabled:
                with self._cache_lock:
                    self.vendor_cache[oui] = "Unknown"
                return "Unknown"

            # Optional online lookup (opt-in) — rate-limited
            url = f"https://api.macvendors.com/{oui}"
            rate = getattr(cfg.security, "rate_limit_delay", 0.01) or 0.01
            time.sleep(rate)

            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    vendor = response.text.strip() or "Unknown"
                    with self._cache_lock:
                        self.vendor_cache[oui] = vendor
                    return vendor
                with self._cache_lock:
                    self.vendor_cache[oui] = "Unknown"
                return "Unknown"
            except requests.exceptions.RequestException as e:
                logger.error("Vendor API error: %s", e)
                with self._cache_lock:
                    self.vendor_cache[oui] = "Unknown"
                return "Unknown"

        except Exception as e:
            logger.error("Unexpected error when getting MAC vendor: %s", e)
            return "Unknown"

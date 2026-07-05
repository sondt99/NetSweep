"""Unit tests for utils/network_utils.py."""
import socket

import utils.network_utils as network_utils_module
from utils.network_utils import get_local_ip, get_local_networks


class FakeSocket:
    def __init__(self, raise_on_connect=False):
        self._raise_on_connect = raise_on_connect

    def connect(self, addr):
        if self._raise_on_connect:
            raise OSError("network unreachable")

    def getsockname(self):
        return ("192.168.1.42", 51000)

    def close(self):
        pass


class TestGetLocalIp:
    def test_returns_detected_ip(self, monkeypatch):
        monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSocket())
        assert get_local_ip() == "192.168.1.42"

    def test_falls_back_to_loopback_on_failure(self, monkeypatch):
        monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSocket(raise_on_connect=True))
        assert get_local_ip() == "127.0.0.1"


class FakeNetifaces:
    """Minimal stand-in for the netifaces module used by get_local_networks."""

    AF_INET = socket.AF_INET
    AF_LINK = 17  # arbitrary distinct constant, matches netifaces.AF_LINK's role

    def __init__(self, interfaces):
        self._interfaces = interfaces

    def interfaces(self):
        return list(self._interfaces.keys())

    def ifaddresses(self, interface):
        return self._interfaces[interface]


class TestGetLocalNetworks:
    def test_includes_the_loopback_interface_itself(self, monkeypatch):
        fake = FakeNetifaces({
            "lo": {socket.AF_INET: [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}]},
        })
        monkeypatch.setattr(network_utils_module, "netifaces", fake)
        monkeypatch.setattr(network_utils_module, "get_interface_friendly_names", lambda: {})

        assert get_local_networks() == [{"interface": "lo", "network": "127.0.0.0/8"}]

    def test_skips_loopback_address_on_a_non_loopback_interface(self, monkeypatch):
        # A 127.x address bound to something other than "lo" is treated as
        # noise (e.g. misconfigured interface) and filtered out.
        fake = FakeNetifaces({
            "eth0": {socket.AF_INET: [{"addr": "127.0.0.1", "netmask": "255.0.0.0"}]},
        })
        monkeypatch.setattr(network_utils_module, "netifaces", fake)
        monkeypatch.setattr(network_utils_module, "get_interface_friendly_names", lambda: {})

        assert get_local_networks() == []

    def test_computes_cidr_for_real_interface(self, monkeypatch):
        fake = FakeNetifaces({
            "eth0": {socket.AF_INET: [{"addr": "192.168.1.10", "netmask": "255.255.255.0"}]},
        })
        monkeypatch.setattr(network_utils_module, "netifaces", fake)
        monkeypatch.setattr(network_utils_module, "get_interface_friendly_names", lambda: {})

        networks = get_local_networks()
        assert networks == [{"interface": "eth0", "network": "192.168.1.0/24"}]

    def test_uses_friendly_name_when_available(self, monkeypatch):
        fake = FakeNetifaces({
            "eth0": {socket.AF_INET: [{"addr": "10.0.0.5", "netmask": "255.255.255.0"}]},
        })
        monkeypatch.setattr(network_utils_module, "netifaces", fake)
        monkeypatch.setattr(network_utils_module, "get_interface_friendly_names", lambda: {"eth0": "Ethernet"})

        networks = get_local_networks()
        assert networks[0]["interface"] == "Ethernet"

    def test_interface_without_ipv4_is_skipped(self, monkeypatch):
        fake = FakeNetifaces({"tun0": {}})
        monkeypatch.setattr(network_utils_module, "netifaces", fake)
        monkeypatch.setattr(network_utils_module, "get_interface_friendly_names", lambda: {})

        assert get_local_networks() == []

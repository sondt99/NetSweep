"""Unit tests for utils/network_utils.py."""
import socket

import utils.network_utils as network_utils_module
from utils.network_utils import get_local_ip, get_local_networks, get_upstream_networks


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


# Real tracepath output captured on the project's own multi-router boarding-house
# LAN: the machine sits on 192.168.0.0/24 behind its room router (192.168.0.1),
# with the shared landlord network 192.168.1.0/24 one hop up, then public hops.
REAL_TRACEPATH_OUTPUT = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.0.1                                           3.475ms
 1:  192.168.0.1                                           0.899ms
 2:  192.168.1.1                                           1.199ms
 3:  192.168.1.1                                           1.338ms pmtu 1438
 3:  203.210.148.17                                        3.231ms
 4:  no reply
 5:  113.171.21.16                                       573.866ms
"""


class TestGetUpstreamNetworks:
    def _patch(self, monkeypatch, trace_output, local_networks):
        monkeypatch.setattr(network_utils_module, "_trace_route", lambda target, max_hops: trace_output)
        monkeypatch.setattr(network_utils_module, "get_local_networks", lambda: local_networks)

    def test_finds_upstream_network_and_excludes_local(self, monkeypatch):
        # 192.168.0.0/24 is local (the room), so only the landlord's 192.168.1.0/24
        # should surface; public hops (203.x, 113.x) must be dropped.
        self._patch(monkeypatch, REAL_TRACEPATH_OUTPUT,
                    [{"interface": "wlp0s20f3", "network": "192.168.0.0/24"}])

        assert get_upstream_networks() == [{"network": "192.168.1.0/24", "via": "192.168.1.1"}]

    def test_returns_empty_when_no_trace_tool(self, monkeypatch):
        self._patch(monkeypatch, None, [])
        assert get_upstream_networks() == []

    def test_dedupes_repeated_and_skips_public_hops(self, monkeypatch):
        # First hop is our own gateway (local), then two distinct private upstream
        # nets each appearing twice, then a public hop that must be ignored.
        output = (
            "1: 192.168.0.1\n1: 192.168.0.1\n"
            "2: 10.10.0.1\n2: 10.10.0.1\n"
            "3: 172.16.5.9\n3: 172.16.5.9\n"
            "4: 8.8.8.8\n"
        )
        self._patch(monkeypatch, output, [{"interface": "eth0", "network": "192.168.0.0/24"}])

        assert get_upstream_networks() == [
            {"network": "10.10.0.0/24", "via": "10.10.0.1"},
            {"network": "172.16.5.0/24", "via": "172.16.5.9"},
        ]

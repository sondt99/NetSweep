"""Unit tests for utils/system_utils.py."""
import socket

import utils.system_utils as system_utils_module
from utils.system_utils import get_local_ip, get_local_mac


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

    def test_returns_none_on_failure(self, monkeypatch):
        monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSocket(raise_on_connect=True))
        assert get_local_ip() is None


class FakeNetifaces:
    AF_LINK = 17

    def __init__(self, interfaces):
        self._interfaces = interfaces

    def interfaces(self):
        return list(self._interfaces.keys())

    def ifaddresses(self, interface):
        return self._interfaces[interface]


class TestGetLocalMac:
    def test_returns_first_valid_mac(self, monkeypatch):
        fake = FakeNetifaces({
            "lo": {FakeNetifaces.AF_LINK: [{"addr": "00:00:00:00:00:00"}]},
            "eth0": {FakeNetifaces.AF_LINK: [{"addr": "aa:bb:cc:dd:ee:ff"}]},
        })
        monkeypatch.setattr(system_utils_module, "netifaces", fake)
        assert get_local_mac() == "AA:BB:CC:DD:EE:FF"

    def test_skips_all_zero_mac(self, monkeypatch):
        fake = FakeNetifaces({
            "lo": {FakeNetifaces.AF_LINK: [{"addr": "00:00:00:00:00:00"}]},
        })
        monkeypatch.setattr(system_utils_module, "netifaces", fake)
        assert get_local_mac() is None

    def test_returns_none_when_no_link_layer_addr(self, monkeypatch):
        fake = FakeNetifaces({"eth0": {}})
        monkeypatch.setattr(system_utils_module, "netifaces", fake)
        assert get_local_mac() is None

    def test_returns_none_on_exception(self, monkeypatch):
        def raise_error():
            raise RuntimeError("no interfaces")

        fake = FakeNetifaces({})
        monkeypatch.setattr(fake, "interfaces", raise_error)
        monkeypatch.setattr(system_utils_module, "netifaces", fake)
        assert get_local_mac() is None

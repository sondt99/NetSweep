"""Unit tests for scanner/device_info.py."""
import socket
import threading

import pytest
import requests

import scanner.device_info as device_info_module
from scanner.device_info import DeviceInfo


@pytest.fixture
def device_info():
    return DeviceInfo()


@pytest.fixture
def local_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    stop = threading.Event()

    def accept_loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        server.close()
        thread.join(timeout=1)


class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class TestCheckDeviceAlive:
    def test_alive_via_open_port(self, device_info, monkeypatch):
        monkeypatch.setattr(device_info, "_check_ports_concurrent", lambda ip: True)
        monkeypatch.setattr(device_info, "_ping", lambda ip: pytest.fail("should not be called"))
        assert device_info.check_device_alive("10.0.0.1") is True

    def test_falls_back_to_ping(self, device_info, monkeypatch):
        monkeypatch.setattr(device_info, "_check_ports_concurrent", lambda ip: False)
        monkeypatch.setattr(device_info, "_ping", lambda ip: True)
        assert device_info.check_device_alive("10.0.0.1") is True

    def test_falls_back_to_arp(self, device_info, monkeypatch):
        monkeypatch.setattr(device_info, "_check_ports_concurrent", lambda ip: False)
        monkeypatch.setattr(device_info, "_ping", lambda ip: False)
        monkeypatch.setattr(device_info, "_check_arp", lambda ip: True)
        assert device_info.check_device_alive("10.0.0.1") is True

    def test_all_checks_fail_returns_false(self, device_info, monkeypatch):
        monkeypatch.setattr(device_info, "_check_ports_concurrent", lambda ip: False)
        monkeypatch.setattr(device_info, "_ping", lambda ip: False)
        monkeypatch.setattr(device_info, "_check_arp", lambda ip: False)
        assert device_info.check_device_alive("10.0.0.1") is False


class TestScanOpenPorts:
    def test_detects_real_open_port(self, device_info, local_listener):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]

        result = device_info.scan_open_ports("127.0.0.1", [local_listener, closed_port], timeout=1.0)
        assert result == [local_listener]

    def test_no_open_ports_returns_empty_list(self, device_info):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        assert device_info.scan_open_ports("127.0.0.1", [closed_port], timeout=0.5) == []


class TestGetMacAddress:
    def test_caches_successful_lookup(self, device_info, monkeypatch):
        calls = []

        def fake_get_mac_address(ip):
            calls.append(ip)
            return "AA:BB:CC:DD:EE:FF"

        monkeypatch.setattr(device_info_module, "get_mac_address", fake_get_mac_address)
        first = device_info.get_mac_address("10.0.0.5")
        second = device_info.get_mac_address("10.0.0.5")

        assert first == "AA:BB:CC:DD:EE:FF"
        assert second == "AA:BB:CC:DD:EE:FF"
        assert calls == ["10.0.0.5"]  # second call served from cache

    def test_returns_none_on_lookup_failure(self, device_info, monkeypatch):
        monkeypatch.setattr(device_info_module, "get_mac_address", lambda ip: None)
        assert device_info.get_mac_address("10.0.0.6") is None

    def test_returns_none_when_lookup_raises(self, device_info, monkeypatch):
        def raise_error(ip):
            raise RuntimeError("no arp")

        monkeypatch.setattr(device_info_module, "get_mac_address", raise_error)
        assert device_info.get_mac_address("10.0.0.7") is None


class TestGetVendor:
    def test_none_mac_returns_na(self, device_info):
        assert device_info.get_vendor(None) == "N/A"

    def test_explicit_na_returns_na(self, device_info):
        assert device_info.get_vendor("N/A") == "N/A"

    def test_locally_administered_mac_is_randomized(self, device_info):
        # Second-least-significant bit of the first octet set -> locally administered.
        assert device_info.get_vendor("02:11:22:33:44:55") == "Randomized/Private MAC"

    def test_successful_lookup_is_cached(self, device_info, monkeypatch):
        calls = []

        def fake_get(url, timeout):
            calls.append(url)
            return FakeResponse(200, "Cisco Systems")

        monkeypatch.setattr(requests, "get", fake_get)
        first = device_info.get_vendor("00:1A:2B:11:22:33")
        second = device_info.get_vendor("00:1A:2B:99:88:77")  # same OUI prefix

        assert first == "Cisco Systems"
        assert second == "Cisco Systems"
        assert len(calls) == 1  # second call hit the OUI cache

    def test_404_is_cached_as_unknown(self, device_info, monkeypatch):
        monkeypatch.setattr(requests, "get", lambda url, timeout: FakeResponse(404))
        assert device_info.get_vendor("00:1A:2B:11:22:33") == "Unknown"

    def test_429_retries_then_succeeds(self, device_info, monkeypatch):
        responses = iter([FakeResponse(429), FakeResponse(200, "Dell Inc.")])
        monkeypatch.setattr(requests, "get", lambda url, timeout: next(responses))
        monkeypatch.setattr(device_info_module.time, "sleep", lambda seconds: None)

        assert device_info.get_vendor("00:1A:2B:11:22:33") == "Dell Inc."

    def test_connection_errors_exhaust_retries_and_return_unknown(self, device_info, monkeypatch):
        def raise_connection_error(url, timeout):
            raise requests.exceptions.RequestException("network down")

        monkeypatch.setattr(requests, "get", raise_connection_error)
        monkeypatch.setattr(device_info_module.time, "sleep", lambda seconds: None)

        assert device_info.get_vendor("00:1A:2B:11:22:33") == "Unknown"

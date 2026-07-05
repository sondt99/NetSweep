"""Unit tests for port_scanner.py's PortScanner class."""
import socket
import threading

import pytest

from port_scanner import PortScanner


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


class FakeTcpLayer:
    def __init__(self, flags):
        self.flags = flags


class FakeIcmpLayer:
    def __init__(self, icmp_type, code):
        self.type = icmp_type
        self.code = code


class FakeResponse:
    def __init__(self, tcp=None, icmp=None):
        self._tcp = tcp
        self._icmp = icmp

    def haslayer(self, layer_cls):
        name = layer_cls if isinstance(layer_cls, str) else layer_cls.__name__
        if name == "TCP":
            return self._tcp is not None
        if name == "ICMP":
            return self._icmp is not None
        return False

    def getlayer(self, layer_cls):
        name = layer_cls if isinstance(layer_cls, str) else layer_cls.__name__
        if name == "TCP":
            return self._tcp
        if name == "ICMP":
            return self._icmp
        return None


class TestTcpConnectScanPort:
    def test_open_port(self, local_listener):
        scanner = PortScanner("127.0.0.1", timeout=1.0)
        port, status = scanner._tcp_connect_scan_port(local_listener)
        assert port == local_listener
        assert status == "open"

    def test_closed_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        scanner = PortScanner("127.0.0.1", timeout=0.5)
        port, status = scanner._tcp_connect_scan_port(closed_port)
        assert port == closed_port
        assert status == "closed"

    def test_tcp_connect_scan_aggregates_results(self, local_listener):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]

        scanner = PortScanner("127.0.0.1", timeout=0.5)
        scanner.tcp_connect_scan([local_listener, closed_port], threads=2)
        assert scanner.open_ports == [local_listener]
        assert closed_port in scanner.closed_ports


class TestSynScanPort:
    """_syn_scan_port drives scapy's sr1(); mocked here to avoid requiring root."""

    def test_syn_ack_marks_port_open(self, monkeypatch):
        import port_scanner as ps_module

        responses = iter([FakeResponse(tcp=FakeTcpLayer(flags=0x12)), FakeResponse(tcp=FakeTcpLayer(flags=0))])
        monkeypatch.setattr(ps_module, "sr1", lambda *a, **k: next(responses))

        scanner = PortScanner("127.0.0.1", timeout=0.1)
        port, status = scanner._syn_scan_port(80)
        assert (port, status) == (80, "open")

    def test_rst_ack_marks_port_closed(self, monkeypatch):
        import port_scanner as ps_module

        monkeypatch.setattr(ps_module, "sr1", lambda *a, **k: FakeResponse(tcp=FakeTcpLayer(flags=0x14)))

        scanner = PortScanner("127.0.0.1", timeout=0.1)
        port, status = scanner._syn_scan_port(81)
        assert (port, status) == (81, "closed")

    def test_no_response_marks_port_filtered(self, monkeypatch):
        import port_scanner as ps_module

        monkeypatch.setattr(ps_module, "sr1", lambda *a, **k: None)

        scanner = PortScanner("127.0.0.1", timeout=0.1)
        port, status = scanner._syn_scan_port(82)
        assert (port, status) == (82, "filtered")

    def test_icmp_unreachable_marks_port_filtered(self, monkeypatch):
        import port_scanner as ps_module

        monkeypatch.setattr(ps_module, "sr1", lambda *a, **k: FakeResponse(icmp=FakeIcmpLayer(3, 1)))

        scanner = PortScanner("127.0.0.1", timeout=0.1)
        port, status = scanner._syn_scan_port(83)
        assert (port, status) == (83, "filtered")


class TestUdpScanPort:
    def test_currently_always_returns_filtered(self):
        # Known pre-existing bug: port_scanner.py imports `UDP` from scapy.all,
        # but scapy.all does not export a bare `UDP` symbol at module import
        # time in this codebase's usage, so `UDP(...)` raises NameError, which
        # is swallowed by the broad except-Exception below and reported as
        # "filtered" instead of crashing. This test locks in that observed
        # behavior; it does not endorse it as correct.
        scanner = PortScanner("127.0.0.1", timeout=0.1)
        port, status = scanner._udp_scan_port(53)
        assert (port, status) == (53, "filtered")


class TestGetResults:
    def test_deduplicates_and_sorts(self):
        scanner = PortScanner("127.0.0.1")
        scanner.open_ports = [80, 22, 80]
        scanner.filtered_ports = [443]
        scanner.closed_ports = [21, 21, 25]

        results = scanner.get_results()
        assert results == {
            "open": [22, 80],
            "filtered": [443],
            "closed": [21, 25],
        }

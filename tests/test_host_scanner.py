"""Unit tests for host_scanner.py."""
import io
import socket
import threading

import pytest

import host_scanner as hs


@pytest.fixture
def local_listener():
    """Bind a real TCP listener on an ephemeral loopback port for open-port tests."""
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


class TestParsePortRange:
    def test_dash_range(self):
        assert list(hs.parse_port_range("1-5")) == [1, 2, 3, 4, 5]

    def test_comma_list(self):
        assert hs.parse_port_range("22,80,443") == [22, 80, 443]

    def test_single_dash_range_is_inclusive_of_end(self):
        assert list(hs.parse_port_range("10-10")) == [10]


class TestGetServiceName:
    def test_known_port(self):
        assert hs.get_service_name(80) == "http"

    def test_unknown_port_returns_unknown(self, monkeypatch):
        def raise_oserror(_port):
            raise OSError("no service")

        monkeypatch.setattr(socket, "getservbyport", raise_oserror)
        assert hs.get_service_name(65000) == "unknown"


class TestScanPort:
    def test_open_port_detected(self, local_listener):
        port, is_open, service = hs.scan_port("127.0.0.1", local_listener, timeout=1.0)
        assert port == local_listener
        assert is_open is True

    def test_open_port_socket_is_closed(self, local_listener, monkeypatch):
        # Regression test: the open-port branch used to return before calling
        # sock.close(), leaking the fd until garbage collection (a real
        # ResourceWarning burst when scanning a host with many open ports).
        created = []
        real_socket = socket.socket

        def tracking_socket(*args, **kwargs):
            sock = real_socket(*args, **kwargs)
            created.append(sock)
            return sock

        monkeypatch.setattr(socket, "socket", tracking_socket)
        hs.scan_port("127.0.0.1", local_listener, timeout=1.0)

        assert created, "scan_port did not create a socket"
        assert created[0].fileno() == -1  # -1 means the socket has been closed

    def test_closed_port_detected(self):
        # Port 1 is a privileged port extremely unlikely to have a listener
        # in a sandboxed test environment, and connect_ex fails fast for
        # closed/refused local ports.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            closed_port = probe.getsockname()[1]
        # probe is now closed and unbound -> nothing listens on closed_port
        port, is_open, service = hs.scan_port("127.0.0.1", closed_port, timeout=0.5)
        assert port == closed_port
        assert is_open is False
        assert service is None


class TestScanPorts:
    def test_finds_open_port_among_range(self, local_listener):
        port_range = f"{local_listener}-{local_listener}"
        results = hs.scan_ports("127.0.0.1", port_range, timeout=1.0, threads=5, verbose=False)
        assert len(results) == 1
        assert results[0][0] == local_listener


class TestGetTtl:
    def test_parses_lowercase_ttl_from_linux_macos_ping(self, monkeypatch):
        # Regression test: get_ttl used to search for "TTL=" (uppercase only),
        # but Linux/macOS `ping` prints lowercase "ttl=NN", so this always
        # returned None (and detect_os always reported "Unknown") on those
        # platforms - which is also this project's primary dev/CI platform.
        sample_output = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=57 time=0.080 ms\n"
        monkeypatch.setattr(hs.os, "popen", lambda cmd: io.StringIO(sample_output))
        assert hs.get_ttl("127.0.0.1") == 57

    def test_parses_uppercase_ttl_from_windows_ping(self, monkeypatch):
        sample_output = "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128\n"
        monkeypatch.setattr(hs.os, "popen", lambda cmd: io.StringIO(sample_output))
        assert hs.get_ttl("127.0.0.1") == 128

    def test_no_ttl_in_output_returns_none(self, monkeypatch):
        monkeypatch.setattr(hs.os, "popen", lambda cmd: io.StringIO("Request timed out.\n"))
        assert hs.get_ttl("127.0.0.1") is None


class TestDetectOs:
    def test_ttl_in_linux_range(self, monkeypatch):
        monkeypatch.setattr(hs, "get_ttl", lambda ip: 60)
        assert hs.detect_os("127.0.0.1", []) == "Linux/Unix"

    def test_ttl_in_windows_range(self, monkeypatch):
        monkeypatch.setattr(hs, "get_ttl", lambda ip: 120)
        assert hs.detect_os("127.0.0.1", []) == "Windows"

    def test_ttl_none_returns_unknown(self, monkeypatch):
        monkeypatch.setattr(hs, "get_ttl", lambda ip: None)
        assert hs.detect_os("127.0.0.1", []) == "Unknown"

    def test_rdp_port_with_non_windows_ttl_yields_hybrid_guess(self, monkeypatch):
        monkeypatch.setattr(hs, "get_ttl", lambda ip: 60)
        result = hs.detect_os("127.0.0.1", [(3389, "rdp")])
        assert result == "Windows or Linux with RDP"


class TestDetectServices:
    def test_ssh_banner_version_extraction(self, monkeypatch):
        monkeypatch.setattr(hs, "get_service_banner", lambda ip, port, timeout: "SSH-2.0-OpenSSH_8.9\r\n")
        results = hs.detect_services("127.0.0.1", [(22, "ssh")], timeout=1.0)
        assert results[0][2] == "SSH-2.0-OpenSSH_8.9"

    def test_apache_banner_version_extraction(self, monkeypatch):
        monkeypatch.setattr(
            hs, "get_service_banner",
            lambda ip, port, timeout: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.1 (Unix)\r\n",
        )
        results = hs.detect_services("127.0.0.1", [(80, "http")], timeout=1.0)
        assert results[0][2] == "Apache 2.4.1"

    def test_nginx_banner_version_extraction(self, monkeypatch):
        monkeypatch.setattr(
            hs, "get_service_banner",
            lambda ip, port, timeout: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n",
        )
        results = hs.detect_services("127.0.0.1", [(80, "http")], timeout=1.0)
        assert results[0][2] == "nginx 1.18.0"

    def test_no_banner_keeps_unknown_version(self, monkeypatch):
        monkeypatch.setattr(hs, "get_service_banner", lambda ip, port, timeout: None)
        results = hs.detect_services("127.0.0.1", [(9999, "unknown")], timeout=1.0)
        assert results[0][2] == "unknown"
        assert results[0][3] is None

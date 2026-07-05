"""Unit tests for service_detector.py."""
import json
import socket
import threading

import pytest

from service_detector import ServiceDetector


@pytest.fixture
def detector():
    return ServiceDetector("127.0.0.1", timeout=1.0)


@pytest.fixture
def echo_server():
    """A real loopback listener that records the first payload it receives."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    received = {}

    def accept_once():
        try:
            conn, _ = server.accept()
            conn.settimeout(2)
            received["data"] = conn.recv(4096)
            conn.close()
        except OSError:
            pass

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    try:
        yield port, received
    finally:
        thread.join(timeout=2)
        server.close()


class TestGetCommonService:
    def test_known_port(self, detector):
        assert detector._get_common_service(22) == "ssh"
        assert detector._get_common_service(443) == "https"

    def test_unknown_port(self, detector):
        assert detector._get_common_service(59999) == "unknown"


class TestGetBanner:
    """Regression tests for the _get_banner "%"-formatting crash.

    _get_banner used to unconditionally apply bytes "%" formatting to
    whichever probe matched the service name, but only the HTTP/HTTPS probes
    contain a "%s" placeholder - every other probe (FTP/SSH/SMTP/POP3/IMAP/
    TELNET's empty b"", and DNS/MYSQL/MSSQL/REDIS/MONGODB's raw binary
    payloads) raised `TypeError: not all arguments converted during bytes
    formatting`, silently swallowed by a broad except, so banner grabbing was
    completely broken for every protocol except HTTP/HTTPS. Verified live
    against a real router's DNS port (53) before this fix.
    """

    @pytest.mark.parametrize("service_name", [
        "FTP", "SSH", "SMTP", "POP3", "IMAP", "TELNET",
        "DNS", "MYSQL", "MSSQL", "REDIS", "MONGODB",
    ])
    def test_non_http_probes_do_not_crash(self, detector, echo_server, service_name):
        port, _ = echo_server
        # Must not raise - previously every one of these raised TypeError,
        # which _get_banner's broad except turned into a silent None.
        detector._get_banner(port, service_name)

    def test_http_probe_is_formatted_with_target_host(self, detector, echo_server):
        port, received = echo_server
        detector._get_banner(port, "HTTP")
        assert b"GET / HTTP/1.1" in received.get("data", b"")
        assert b"Host: 127.0.0.1" in received.get("data", b"")

    def test_binary_probe_sent_as_is(self, detector, echo_server):
        port, received = echo_server
        detector._get_banner(port, "REDIS")
        assert received.get("data") == b"INFO\r\n"

    def test_empty_probe_sends_nothing(self, detector, echo_server):
        port, received = echo_server
        detector._get_banner(port, "SSH")
        assert received.get("data", b"") == b""

    @pytest.mark.parametrize("alt_name", [
        "http-proxy",  # port 8080's common-service name
        "https-alt",   # port 8443's common-service name
    ])
    def test_alt_http_port_names_route_to_the_real_http_probe(self, detector, echo_server, alt_name):
        # Regression test: _get_common_service(8080) returns "http-proxy" and
        # _get_common_service(8443) returns "https-alt", neither of which is a
        # key in service_probes (only "HTTP"/"HTTPS" are) - so these very
        # common LAN alt-HTTP ports used to silently fall back to the generic
        # b"\r\n\r\n" probe instead of a real HTTP request.
        port, received = echo_server
        detector._get_banner(port, alt_name)
        assert b"GET / HTTP/1.1" in received.get("data", b"")

    def test_unrecognized_service_uses_generic_probe(self, detector, echo_server):
        port, received = echo_server
        detector._get_banner(port, "unknown")
        assert received.get("data") == b"\r\n\r\n"


class TestExtractCertNames:
    def test_extracts_common_name_org_and_unit(self, detector):
        rdns = (
            (("commonName", "example.com"),),
            (("organizationName", "Example Inc"),),
            (("organizationalUnitName", "IT"),),
        )
        assert detector._extract_cert_names(rdns) == {
            "CN": "example.com",
            "O": "Example Inc",
            "OU": "IT",
        }

    def test_ignores_unrecognized_fields(self, detector):
        rdns = ((("countryName", "US"),),)
        assert detector._extract_cert_names(rdns) == {}

    def test_empty_input_returns_empty_dict(self, detector):
        assert detector._extract_cert_names(()) == {}


class TestIdentifyServiceFromBanner:
    def test_http_with_server_header(self, detector):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
        service, version = detector._identify_service_from_banner(banner, "unknown", 80)
        assert service == "http"
        assert version == "nginx/1.18.0"

    def test_https_with_ssl_flag(self, detector):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n"
        service, version = detector._identify_service_from_banner(banner, "unknown", 443, ssl=True)
        assert service == "https"

    def test_ssh_banner(self, detector):
        banner = "SSH-2.0-OpenSSH_8.9"
        service, version = detector._identify_service_from_banner(banner, "unknown", 22)
        assert service == "ssh"
        assert version == "SSH-2.0-OpenSSH_8.9"

    def test_ftp_banner(self, detector):
        banner = "220 Welcome to FTP server"
        service, version = detector._identify_service_from_banner(banner, "unknown", 21)
        assert service == "ftp"
        assert version == "Welcome to FTP server"

    def test_220_banner_is_classified_as_ftp_before_smtp(self, detector):
        # FTP and SMTP share the identical "^220[ -](.*)$" greeting pattern,
        # and the FTP branch is checked first in the classification cascade -
        # so a plain SMTP greeting is (mis)classified as ftp. This locks in
        # that existing, pre-refactor behavior rather than the "correct" one.
        banner = "220 mail.example.com ESMTP Postfix"
        service, version = detector._identify_service_from_banner(banner, "unknown", 25)
        assert service == "ftp"

    def test_pop3_banner(self, detector):
        banner = "+OK POP3 server ready"
        service, version = detector._identify_service_from_banner(banner, "unknown", 110)
        assert service == "pop3"

    def test_imap_banner(self, detector):
        banner = "* OK IMAP4rev1 Service Ready"
        service, version = detector._identify_service_from_banner(banner, "unknown", 143)
        assert service == "imap"

    def test_redis_banner(self, detector):
        banner = "redis_version:7.0.5\r\nother stuff"
        service, version = detector._identify_service_from_banner(banner, "unknown", 6379)
        assert service == "redis"
        assert version == "7.0.5"

    def test_generic_nginx_fallback(self, detector):
        banner = "some garbage but mentions nginx/1.20.1 somewhere"
        service, version = detector._identify_service_from_banner(banner, "unknown", 8080)
        assert version == "nginx/1.20.1"

    def test_generic_apache_fallback(self, detector):
        banner = "garbled apache/2.4.41 text"
        service, version = detector._identify_service_from_banner(banner, "unknown", 8081)
        assert version == "Apache/2.4.41"

    def test_unmatched_banner_keeps_unknown_version(self, detector):
        banner = "completely unrecognized protocol data"
        service, version = detector._identify_service_from_banner(banner, "custom", 9999)
        assert version == "unknown"
        assert service == "custom"


class TestExportToJson:
    def test_writes_structured_json_under_target_directory(self, detector, tmp_path, monkeypatch):
        # export_to_json resolves its output directory relative to this
        # module's own __file__; redirect that into tmp_path so the test
        # never touches the real repo tree.
        import service_detector as sd_module

        monkeypatch.setattr(sd_module, "__file__", str(tmp_path / "service_detector.py"))

        results = [
            {"port": 22, "service": "ssh", "version": "OpenSSH_8.9", "banner": "SSH-2.0-OpenSSH_8.9", "ssl_cert": None},
            {"port": 80, "service": "unknown", "version": "unknown", "banner": None, "ssl_cert": None},
        ]
        output_file = detector.export_to_json(results)

        assert output_file.startswith(str(tmp_path / "results" / "127.0.0.1"))
        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)

        assert data["target"] == "127.0.0.1"
        assert data["ports_scanned"] == 2
        assert len(data["open_ports"]) == 1
        assert data["open_ports"][0]["port"] == 22

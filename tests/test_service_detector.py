"""Unit tests for service_detector.py."""
import json

import pytest

from service_detector import ServiceDetector


@pytest.fixture
def detector():
    return ServiceDetector("127.0.0.1", timeout=1.0)


class TestGetCommonService:
    def test_known_port(self, detector):
        assert detector._get_common_service(22) == "ssh"
        assert detector._get_common_service(443) == "https"

    def test_unknown_port(self, detector):
        assert detector._get_common_service(59999) == "unknown"


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

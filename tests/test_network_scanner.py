"""Unit tests for scanner/network_scanner.py."""
import csv
import json
import os

import pytest

from scanner.network_scanner import NetworkScanner, DISCOVERY_PORT_SERVICES


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    # Run from tmp_path so `_load_known_devices` doesn't find a stray
    # config/known_devices.json, and output_dir stays isolated from the repo.
    monkeypatch.chdir(tmp_path)
    return NetworkScanner("192.168.1.0/30", output_dir=str(tmp_path / "scan_results"))


class TestDiscoveryPortServices:
    def test_known_ports_have_labels(self):
        assert DISCOVERY_PORT_SERVICES[80] == "http"
        assert DISCOVERY_PORT_SERVICES[22] == "ssh"


class TestLoadKnownDevices:
    def test_defaults_used_when_no_file_present(self, scanner):
        assert "192.168.1.1" in scanner.known_devices
        assert scanner.known_devices["192.168.1.1"]["name"] == "Router"

    def test_loads_from_existing_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        os.makedirs("config", exist_ok=True)
        with open("config/known_devices.json", "w", encoding="utf-8") as f:
            json.dump({"10.0.0.5": {"name": "NAS", "type": "storage"}}, f)

        scanner = NetworkScanner("192.168.1.0/30", output_dir=str(tmp_path / "out"))
        assert scanner.known_devices == {"10.0.0.5": {"name": "NAS", "type": "storage"}}


class TestDetermineDeviceType:
    def test_no_ports_is_unknown(self, scanner):
        assert scanner._determine_device_type([]) == "Unknown"

    def test_camera_signature_takes_priority(self, scanner):
        assert scanner._determine_device_type(["554(rtsp)", "80(http)", "443(https)"]) == "Camera/Media Device"

    def test_web_server_signature(self, scanner):
        result = scanner._determine_device_type(["80(http)", "443(https)", "8080(http-proxy)"])
        assert result == "Web Server"

    def test_web_device_signature(self, scanner):
        result = scanner._determine_device_type(["80(http)", "8443(https-alt)"])
        assert result == "Web Device"

    def test_linux_signature(self, scanner):
        assert scanner._determine_device_type(["22(ssh)"]) == "Linux/Unix Device"

    def test_windows_signature_overrides_ssh(self, scanner):
        assert scanner._determine_device_type(["22(ssh)", "3389(rdp)"]) == "Windows Device"

    def test_dns_signature(self, scanner):
        assert scanner._determine_device_type(["53(dns)"]) == "DNS Server"

    def test_mail_signature(self, scanner):
        assert scanner._determine_device_type(["25(smtp)"]) == "Mail Server"

    def test_ftp_signature(self, scanner):
        assert scanner._determine_device_type(["21(ftp)"]) == "FTP Server"

    def test_iot_signature(self, scanner):
        assert scanner._determine_device_type(["1883(mqtt)"]) == "IoT Device"

    def test_unrecognized_ports_are_generic(self, scanner):
        assert scanner._determine_device_type(["9999(abyss)"]) == "Generic Device"

    def test_port_8000_alone_is_not_a_camera(self, scanner):
        # Regression test: 8000 alone used to also trigger the camera branch,
        # but it's a generic alt-HTTP port (dev servers/NAS/printers/Sonos),
        # not camera-specific. Verified live: a laptop NIC exposing only 8000
        # was misreported as "Camera/Media Device" before this fix.
        assert scanner._determine_device_type(["8000(http-alt)"]) == "Generic Device"

    def test_port_8000_with_rtsp_is_still_a_camera(self, scanner):
        assert scanner._determine_device_type(["554(rtsp)", "8000(http-alt)"]) == "Camera/Media Device"


class TestScanKeepsAliveHostsWithNoInfo:
    def test_alive_host_with_no_mac_or_ports_is_still_reported(self, scanner, monkeypatch):
        # Regression test: scan_ip() only returns non-None once
        # check_device_alive() has already confirmed liveness (via port probe,
        # ping, or ARP/neighbor-table fallback), and its own inline comment
        # says "Add to results even if MAC or ports are N/A" - but scan()'s
        # results filter used to additionally require a resolved MAC or an
        # open port, silently dropping genuinely-alive hosts and undercounting
        # devices_found. 192.168.1.0/30 has exactly 2 usable hosts.
        def fake_scan_ip(ip):
            return {
                "ip": str(ip), "mac": "N/A", "vendor": "N/A", "ports": "N/A",
                "type": "Unknown", "name": "Unknown", "scan_time": "2026-01-01 00:00:00",
            }

        monkeypatch.setattr(scanner, "scan_ip", fake_scan_ip)
        results = scanner.scan(export_format=None)

        assert scanner.devices_found == 2
        assert len(results) == 2
        assert all(r["mac"] == "N/A" and r["ports"] == "N/A" for r in results)

    def test_dead_hosts_are_not_reported(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "scan_ip", lambda ip: None)
        results = scanner.scan(export_format=None)
        assert scanner.devices_found == 0
        assert results == []


class TestExportResults:
    def _sample_results(self):
        return [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Cisco",
             "type": "Router", "ports": "80(http)", "name": "Router", "scan_time": "2026-01-01 00:00:00"},
        ]

    def test_no_results_skips_export(self, scanner, capsys):
        scanner.results = []
        scanner.export_results("json")
        assert "No devices found" in capsys.readouterr().out

    def test_json_export(self, scanner, tmp_path):
        scanner.results = self._sample_results()
        scanner.export_results("json")
        files = list((tmp_path / "scan_results").glob("scan_*.json"))
        assert len(files) == 1
        with open(files[0], encoding="utf-8") as f:
            data = json.load(f)
        assert data[0]["ip"] == "192.168.1.1"

    def test_csv_export(self, scanner, tmp_path):
        scanner.results = self._sample_results()
        scanner.export_results("csv")
        files = list((tmp_path / "scan_results").glob("scan_*.csv"))
        assert len(files) == 1
        with open(files[0], encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["ip"] == "192.168.1.1"

    def test_txt_export(self, scanner, tmp_path):
        scanner.results = self._sample_results()
        scanner.export_results("txt")
        files = list((tmp_path / "scan_results").glob("scan_*.txt"))
        assert len(files) == 1
        assert "192.168.1.1" in files[0].read_text()

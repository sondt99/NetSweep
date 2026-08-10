"""Regression tests for NetSweep v5.0.0 security/correctness fixes."""
import ipaddress

import pytest

import netsweep.cli.menu as main
from netsweep.config import get_config_manager, SecurityConfig
from netsweep.cli.host import parse_port_range
from netsweep.scan.service import redact_banner, MAX_BANNER_BYTES
from netsweep.scan.network import _count_scan_hosts, NetworkScanner
from netsweep.data.oui import lookup_oui_offline


class TestConfigResetMenu:
    def test_reset_via_manager_not_dataclass(self, tmp_path):
        manager = get_config_manager()
        # Must not raise AttributeError on manager
        manager.reset_to_defaults()
        assert manager.get_config().scan.timeout > 0
        # Dataclass snapshot still has no reset_to_defaults
        cfg = manager.get_config()
        assert not hasattr(cfg, "reset_to_defaults")


class TestParsePortRange:
    def test_valid_range(self):
        assert parse_port_range("1-3") == [1, 2, 3]

    def test_rejects_inverted(self):
        with pytest.raises(ValueError):
            parse_port_range("1000-1")

    def test_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            parse_port_range("0-10")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            parse_port_range("")


class TestBannerRedaction:
    def test_set_cookie_redacted(self):
        raw = "HTTP/1.1 200 OK\r\nSet-Cookie: SID=secret\r\n\r\nbody"
        out = redact_banner(raw)
        assert "secret" not in out
        assert "REDACTED" in out
        assert "body" not in out  # headers only

    def test_size_cap(self):
        big = "X" * (MAX_BANNER_BYTES + 100)
        out = redact_banner(big)
        assert len(out) <= MAX_BANNER_BYTES + len("...[truncated]")


class TestHostEnumeration:
    def test_slash_32_counts_one(self):
        net = ipaddress.ip_network("10.0.0.5/32")
        assert _count_scan_hosts(net) == 1

    def test_max_targets_enforced(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        scanner = NetworkScanner("10.0.0.0/16", output_dir=str(tmp_path / "out"), assume_yes=True)
        # Force tiny limit
        from config import get_config

        get_config().security.max_scan_targets = 10
        with pytest.raises(ValueError, match="max_scan_targets"):
            scanner.scan()


class TestOfflineOui:
    def test_vmware_oui(self):
        assert lookup_oui_offline("00:0C:29:aa:bb:cc") == "VMware"


class TestLanVerboseFlag:
    def test_build_args_common_can_emit_v(self):
        answers = iter(["", "", "", "", "y"])
        result = main.build_args_common(input_func=lambda _p: next(answers))
        assert "-v" in result

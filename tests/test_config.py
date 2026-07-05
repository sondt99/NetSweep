"""Unit tests for config.py (ConfigManager, dataclasses, module-level helpers)."""
import json

import pytest

from config import (
    ConfigManager,
    NetSweepConfig,
    NetworkConfig,
    OutputConfig,
    ScanConfig,
    SecurityConfig,
)


class TestDefaultConfig:
    def test_scan_defaults(self):
        cfg = NetSweepConfig()
        assert cfg.scan.timeout == 0.5
        assert cfg.scan.max_workers == 50
        assert cfg.scan.retry_count == 3

    def test_network_defaults_populate_common_ports(self):
        cfg = NetSweepConfig()
        assert cfg.network.default_ports == "1-1000"
        assert isinstance(cfg.network.common_ports_range, list)
        assert 80 in cfg.network.common_ports_range
        assert 443 in cfg.network.common_ports_range
        assert cfg.network.exclude_ports == []

    def test_output_and_security_defaults(self):
        cfg = NetSweepConfig()
        assert cfg.output.export_format == "json"
        assert cfg.output.verbose is False
        assert cfg.security.max_scan_targets == 1000

    def test_explicit_sections_are_not_overridden(self):
        # __post_init__ should not clobber explicitly-provided sub-configs.
        custom_scan = ScanConfig(timeout=9.9)
        cfg = NetSweepConfig(scan=custom_scan)
        assert cfg.scan.timeout == 9.9


class TestConfigManager:
    def _manager(self, tmp_path):
        return ConfigManager(config_file=str(tmp_path / "config.json"))

    def test_uses_defaults_when_no_file_exists(self, tmp_path):
        manager = self._manager(tmp_path)
        assert manager.get_config().scan.max_workers == 50

    def test_save_then_load_roundtrip(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(scan=ScanConfig(max_workers=123, timeout=1.25))
        manager.save_config()

        reloaded = ConfigManager(config_file=manager.config_file)
        assert reloaded.get_config().scan.max_workers == 123
        assert reloaded.get_config().scan.timeout == 1.25

    def test_save_config_writes_valid_json(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.save_config()
        with open(manager.config_file, encoding="utf-8") as f:
            data = json.load(f)
        assert set(data.keys()) == {"scan", "network", "output", "security"}

    def test_update_config_only_sets_known_attributes(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(scan=ScanConfig(max_workers=7), bogus_field="ignored")
        assert manager.get_config().scan.max_workers == 7
        assert not hasattr(manager.get_config(), "bogus_field")

    def test_reset_to_defaults(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(scan=ScanConfig(max_workers=999))
        manager.reset_to_defaults()
        assert manager.get_config().scan.max_workers == 50

    def test_load_config_falls_back_to_defaults_on_corrupt_file(self, tmp_path, capsys):
        config_file = tmp_path / "config.json"
        config_file.write_text("{not valid json", encoding="utf-8")
        manager = ConfigManager(config_file=str(config_file))
        assert manager.get_config().scan.max_workers == 50
        assert "Warning" in capsys.readouterr().out

    def test_get_effective_config_contains_dotted_keys(self, tmp_path):
        manager = self._manager(tmp_path)
        effective = manager.get_effective_config()
        assert effective["scan.max_workers"] == 50
        assert effective["network.default_ports"] == "1-1000"


class TestValidateConfig:
    def _manager(self, tmp_path):
        return ConfigManager(config_file=str(tmp_path / "config.json"))

    def test_valid_default_config_has_no_errors(self, tmp_path):
        manager = self._manager(tmp_path)
        assert manager.validate_config() == []

    @pytest.mark.parametrize(
        "scan_kwargs",
        [
            {"timeout": 0},
            {"timeout": -1},
            {"max_workers": 0},
            {"retry_count": -1},
        ],
    )
    def test_invalid_scan_values_are_flagged(self, tmp_path, scan_kwargs):
        manager = self._manager(tmp_path)
        manager.update_config(scan=ScanConfig(**scan_kwargs))
        assert manager.validate_config() != []

    def test_invalid_port_range_is_flagged(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(network=NetworkConfig(default_ports="1000-1"))
        errors = manager.validate_config()
        assert any("port range" in e.lower() for e in errors)

    def test_invalid_export_format_is_flagged(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(output=OutputConfig(export_format="xml"))
        errors = manager.validate_config()
        assert any("export format" in e.lower() for e in errors)

    def test_invalid_security_values_are_flagged(self, tmp_path):
        manager = self._manager(tmp_path)
        manager.update_config(security=SecurityConfig(max_scan_targets=0, max_concurrent_connections=0))
        errors = manager.validate_config()
        assert len(errors) == 2

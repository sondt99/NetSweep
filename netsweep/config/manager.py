"""Configuration manager and accessors for NetSweep."""
from __future__ import annotations

import json
import os
from pathlib import Path
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from netsweep.config.models import (
    NetSweepConfig,
    NetworkConfig,
    OutputConfig,
    ScanConfig,
    SecurityConfig,
)

_config_manager: Optional["ConfigManager"] = None


class ConfigManager:
    """Professional configuration management for NetSweep."""

    def __init__(self, config_file: Optional[str] = None) -> None:
        self.config_file = config_file or self._get_default_config_path()
        self.config = NetSweepConfig()
        self.load_config()

    def _get_default_config_path(self) -> str:
        home_dir = Path.home()
        netsweep_dir = home_dir / ".netsweep"
        netsweep_dir.mkdir(exist_ok=True)
        return str(netsweep_dir / "config.json")

    def load_config(self) -> None:
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
                if "scan" in config_data:
                    self.config.scan = ScanConfig(**config_data["scan"])
                if "network" in config_data:
                    self.config.network = NetworkConfig(**config_data["network"])
                if "output" in config_data:
                    self.config.output = OutputConfig(**config_data["output"])
                if "security" in config_data:
                    self.config.security = SecurityConfig(**config_data["security"])
        except Exception as e:
            print(f"Warning: Could not load configuration from {self.config_file}: {e}")
            print("Using default configuration values")

    def save_config(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            config_dict = {
                "scan": asdict(self.config.scan),
                "network": asdict(self.config.network),
                "output": asdict(self.config.output),
                "security": asdict(self.config.security),
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving configuration to {self.config_file}: {e}")

    def get_config(self) -> NetSweepConfig:
        return self.config

    def update_config(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    def reset_to_defaults(self) -> None:
        self.config = NetSweepConfig()

    def validate_config(self) -> List[str]:
        errors: List[str] = []
        if self.config.scan.timeout <= 0:
            errors.append("Scan timeout must be positive")
        if self.config.scan.max_workers <= 0:
            errors.append("Max workers must be positive")
        if self.config.scan.retry_count < 0:
            errors.append("Retry count cannot be negative")
        if self.config.network.default_ports:
            try:
                if "-" in str(self.config.network.default_ports):
                    start, end = map(int, str(self.config.network.default_ports).split("-"))
                    if start <= 0 or end <= 0 or start > end:
                        errors.append("Invalid port range format")
            except ValueError:
                errors.append("Invalid default ports format")
        if self.config.output.export_format not in ["json", "csv", "txt"]:
            errors.append("Invalid export format")
        if self.config.security.max_scan_targets <= 0:
            errors.append("Max scan targets must be positive")
        if self.config.security.max_concurrent_connections <= 0:
            errors.append("Max concurrent connections must be positive")
        if getattr(self.config.security, "max_threads", 200) <= 0:
            errors.append("Max threads must be positive")
        if self.config.scan.max_workers > getattr(self.config.security, "max_threads", 200):
            errors.append("scan.max_workers exceeds security.max_threads")
        return errors

    def get_effective_config(self) -> Dict[str, Any]:
        return {
            "scan.timeout": self.config.scan.timeout,
            "scan.max_workers": self.config.scan.max_workers,
            "scan.retry_count": self.config.scan.retry_count,
            "scan.banner_grab_timeout": self.config.scan.banner_grab_timeout,
            "scan.scan_delay": self.config.scan.scan_delay,
            "network.default_ports": self.config.network.default_ports,
            "network.common_ports_range": self.config.network.common_ports_range,
            "network.exclude_ports": self.config.network.exclude_ports,
            "network.interface_timeout": self.config.network.interface_timeout,
            "output.default_output_dir": self.config.output.default_output_dir,
            "output.export_format": self.config.output.export_format,
            "output.verbose": self.config.output.verbose,
            "output.show_progress": self.config.output.show_progress,
            "output.table_style": self.config.output.table_style,
            "security.max_scan_targets": self.config.security.max_scan_targets,
            "security.max_concurrent_connections": self.config.security.max_concurrent_connections,
            "security.max_threads": getattr(self.config.security, "max_threads", 200),
            "security.rate_limit_delay": self.config.security.rate_limit_delay,
            "security.require_user_confirmation": self.config.security.require_user_confirmation,
            "security.allow_public_targets": getattr(self.config.security, "allow_public_targets", False),
            "security.online_vendor_lookup": getattr(self.config.security, "online_vendor_lookup", False),
        }


def get_config_manager(config_file: Optional[str] = None) -> ConfigManager:
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
    return _config_manager


def get_config() -> NetSweepConfig:
    return get_config_manager().get_config()


def clamp_threads(requested: int) -> int:
    sec = get_config().security
    max_t = max(1, int(getattr(sec, "max_threads", 200)))
    return max(1, min(int(requested), max_t))


def create_default_config_file(file_path: str) -> None:
    manager = ConfigManager(file_path)
    manager.save_config()
    print(f"Default configuration created at: {file_path}")

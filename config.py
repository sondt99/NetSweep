#!/usr/bin/env python3
"""
Centralized configuration for NetSweep
Professional configuration management system
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any


@dataclass
class ScanConfig:
    """Configuration for scanning operations"""
    timeout: float = 0.5
    max_workers: int = 50
    retry_count: int = 3
    banner_grab_timeout: float = 1.0
    scan_delay: float = 0.1


@dataclass
class NetworkConfig:
    """Network-related configuration"""
    default_ports: str = "1-1000"
    common_ports_range: List[int] = None
    exclude_ports: List[int] = None
    interface_timeout: float = 2.0


@dataclass
class OutputConfig:
    """Output and logging configuration"""
    default_output_dir: str = "scan_results"
    export_format: str = "json"  # json, csv, txt
    verbose: bool = False
    show_progress: bool = True
    table_style: str = "grid"


@dataclass
class SecurityConfig:
    """Security and limits configuration"""
    max_scan_targets: int = 1000
    max_concurrent_connections: int = 200
    rate_limit_delay: float = 0.01
    require_user_confirmation: bool = True


@dataclass
class NetSweepConfig:
    """Main NetSweep configuration class"""
    scan: ScanConfig = None
    network: NetworkConfig = None
    output: OutputConfig = None
    security: SecurityConfig = None

    def __post_init__(self):
        """Initialize default configurations"""
        if self.scan is None:
            self.scan = ScanConfig()
        if self.network is None:
            self.network = NetworkConfig(
                common_ports_range=[21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                                  443, 993, 995, 1723, 3306, 3389, 5432, 5900,
                                  8080, 8443],
                exclude_ports=[]
            )
        if self.output is None:
            self.output = OutputConfig()
        if self.security is None:
            self.security = SecurityConfig()


class ConfigManager:
    """Professional configuration management for NetSweep"""

    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration manager

        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file or self._get_default_config_path()
        self.config = NetSweepConfig()
        self.load_config()

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        netsweep_dir = home_dir / ".netsweep"
        netsweep_dir.mkdir(exist_ok=True)
        return str(netsweep_dir / "config.json")

    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)

                # Update configuration with loaded data
                if 'scan' in config_data:
                    self.config.scan = ScanConfig(**config_data['scan'])
                if 'network' in config_data:
                    self.config.network = NetworkConfig(**config_data['network'])
                if 'output' in config_data:
                    self.config.output = OutputConfig(**config_data['output'])
                if 'security' in config_data:
                    self.config.security = SecurityConfig(**config_data['security'])

        except Exception as e:
            print(f"Warning: Could not load configuration from {self.config_file}: {e}")
            print("Using default configuration values")

    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

            config_dict = {
                'scan': asdict(self.config.scan),
                'network': asdict(self.config.network),
                'output': asdict(self.config.output),
                'security': asdict(self.config.security)
            }

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)

        except Exception as e:
            print(f"Error saving configuration to {self.config_file}: {e}")

    def get_config(self) -> NetSweepConfig:
        """Get current configuration"""
        return self.config

    def update_config(self, **kwargs) -> None:
        """Update configuration with provided values

        Args:
            **kwargs: Configuration values to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.config = NetSweepConfig()

    def validate_config(self) -> List[str]:
        """Validate current configuration

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate scan configuration
        if self.config.scan.timeout <= 0:
            errors.append("Scan timeout must be positive")
        if self.config.scan.max_workers <= 0:
            errors.append("Max workers must be positive")
        if self.config.scan.retry_count < 0:
            errors.append("Retry count cannot be negative")

        # Validate network configuration
        if self.config.network.default_ports:
            try:
                if '-' in str(self.config.network.default_ports):
                    start, end = map(int, str(self.config.network.default_ports).split('-'))
                    if start <= 0 or end <= 0 or start > end:
                        errors.append("Invalid port range format")
            except ValueError:
                errors.append("Invalid default ports format")

        # Validate output configuration
        if self.config.output.export_format not in ['json', 'csv', 'txt']:
            errors.append("Invalid export format")

        # Validate security configuration
        if self.config.security.max_scan_targets <= 0:
            errors.append("Max scan targets must be positive")
        if self.config.security.max_concurrent_connections <= 0:
            errors.append("Max concurrent connections must be positive")

        return errors

    def get_effective_config(self) -> Dict[str, Any]:
        """Get effective configuration as dictionary

        Returns:
            Dictionary containing all effective configuration values
        """
        return {
            'scan.timeout': self.config.scan.timeout,
            'scan.max_workers': self.config.scan.max_workers,
            'scan.retry_count': self.config.scan.retry_count,
            'scan.banner_grab_timeout': self.config.scan.banner_grab_timeout,
            'scan.scan_delay': self.config.scan.scan_delay,
            'network.default_ports': self.config.network.default_ports,
            'network.common_ports_range': self.config.network.common_ports_range,
            'network.exclude_ports': self.config.network.exclude_ports,
            'network.interface_timeout': self.config.network.interface_timeout,
            'output.default_output_dir': self.config.output.default_output_dir,
            'output.export_format': self.config.output.export_format,
            'output.verbose': self.config.output.verbose,
            'output.show_progress': self.config.output.show_progress,
            'output.table_style': self.config.output.table_style,
            'security.max_scan_targets': self.config.security.max_scan_targets,
            'security.max_concurrent_connections': self.config.security.max_concurrent_connections,
            'security.rate_limit_delay': self.config.security.rate_limit_delay,
            'security.require_user_confirmation': self.config.security.require_user_confirmation,
        }


# Global configuration manager instance
_config_manager = None


def get_config_manager(config_file: Optional[str] = None) -> ConfigManager:
    """Get global configuration manager instance

    Args:
        config_file: Path to configuration file (optional)

    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file)
    return _config_manager


def get_config() -> NetSweepConfig:
    """Get current configuration

    Returns:
        Current NetSweepConfig instance
    """
    return get_config_manager().get_config()


def create_default_config_file(file_path: str) -> None:
    """Create a default configuration file

    Args:
        file_path: Path where to create the configuration file
    """
    manager = ConfigManager(file_path)
    manager.save_config()
    print(f"Default configuration created at: {file_path}")


if __name__ == "__main__":
    # Example usage and configuration file creation
    import argparse

    parser = argparse.ArgumentParser(description="NetSweep Configuration Management")
    parser.add_argument("--create-config", help="Create default configuration file")
    parser.add_argument("--show-config", action="store_true", help="Show current configuration")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")

    args = parser.parse_args()

    if args.create_config:
        create_default_config_file(args.create_config)

    if args.show_config:
        manager = get_config_manager()
        config = manager.get_config()
        print("Current NetSweep Configuration:")
        print(json.dumps(manager.get_effective_config(), indent=2))

    if args.validate:
        manager = get_config_manager()
        errors = manager.validate_config()
        if errors:
            print("Configuration validation errors:")
            for error in errors:
                print(f"  - {error}")
        else:
            print("Configuration is valid!")
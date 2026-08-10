"""Configuration CLI: python -m netsweep.config or netsweep config helpers."""
from __future__ import annotations

import argparse
import json

from netsweep.config import create_default_config_file, get_config_manager


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="NetSweep Configuration Management")
    parser.add_argument("--create-config", help="Create default configuration file")
    parser.add_argument("--show-config", action="store_true", help="Show current configuration")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    args = parser.parse_args(argv)

    if args.create_config:
        create_default_config_file(args.create_config)
    if args.show_config:
        manager = get_config_manager()
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


if __name__ == "__main__":
    main()

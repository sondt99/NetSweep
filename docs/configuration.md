# Configuration

NetSweep stores persistent settings in a JSON file managed by `ConfigManager`.

## Location

| Path | Role |
|------|------|
| `~/.netsweep/config.json` | Default user config (created as needed) |
| Custom path | `ConfigManager(config_file=...)` or `--create-config PATH` |

The directory `~/.netsweep/` is created on first access.

## View / validate / reset

```bash
python -m netsweep.cli.config_cmd --show-config
python -m netsweep.cli.config_cmd --validate

# Interactive: netsweep menu → Configuration
# Reset defaults: menu option 3 → confirms and save_config()
```

## Schema overview

Config is split into four sections (dataclasses in `netsweep.config.models`).

### `scan`

| Key | Type | Default | Used for |
|-----|------|---------|----------|
| `timeout` | float | `0.5` | Default socket timeout (LAN/host CLIs load this) |
| `max_workers` | int | `50` | Default thread count |
| `retry_count` | int | `3` | Reserved / partial use |
| `banner_grab_timeout` | float | `1.0` | Documented banner budget |
| `scan_delay` | float | `0.1` | Soft delay between enrichment steps |

### `network`

| Key | Type | Default | Used for |
|-----|------|---------|----------|
| `default_ports` | str | `"1-1000"` | Host CLI default `-p` |
| `common_ports_range` | list[int] | nmap-like top ports + MQTT | LAN discovery port set |
| `exclude_ports` | list[int] | `[]` | Reserved |
| `interface_timeout` | float | `2.0` | Reserved |

### `output`

| Key | Type | Default | Used for |
|-----|------|---------|----------|
| `default_output_dir` | str | `"scan_results"` | LAN `-d` default |
| `export_format` | str | `"json"` | Menu default for LAN export |
| `verbose` | bool | `false` | Menu default for `-v` |
| `show_progress` | bool | `true` | Progress UI intent |
| `table_style` | str | `"grid"` | Tabulate style intent |

### `security` (enforced at runtime)

| Key | Type | Default | Enforcement |
|-----|------|---------|-------------|
| `max_scan_targets` | int | `1000` | LAN refuses larger host counts |
| `max_concurrent_connections` | int | `200` | Global semaphore for concurrent sockets |
| `max_threads` | int | `200` | `clamp_threads()` on worker pools |
| `rate_limit_delay` | float | `0.01` | Applied when online vendor lookup is used |
| `require_user_confirmation` | bool | `true` | Prompts for large/public scopes |
| `allow_public_targets` | bool | `false` | Host non-private targets need confirm (or allow) |
| `online_vendor_lookup` | bool | `false` | Offline OUI unless true / allow_online |

## Example `config.json`

```json
{
  "scan": {
    "timeout": 0.5,
    "max_workers": 50,
    "retry_count": 3,
    "banner_grab_timeout": 1.0,
    "scan_delay": 0.1
  },
  "network": {
    "default_ports": "1-1000",
    "common_ports_range": null,
    "exclude_ports": [],
    "interface_timeout": 2.0
  },
  "output": {
    "default_output_dir": "scan_results",
    "export_format": "json",
    "verbose": false,
    "show_progress": true,
    "table_style": "grid"
  },
  "security": {
    "max_scan_targets": 1000,
    "max_concurrent_connections": 200,
    "max_threads": 200,
    "rate_limit_delay": 0.01,
    "require_user_confirmation": true,
    "allow_public_targets": false,
    "online_vendor_lookup": false
  }
}
```

`common_ports_range: null` is filled with built-in defaults when loaded via dataclasses / defaults.

## Known devices file (LAN names)

`NetworkScanner` may load friendly names from (first hit wins):

1. `./config/known_devices.json` (cwd)  
2. `~/.netsweep/known_devices.json`  
3. Package-relative `config/known_devices.json` if present  

Example:

```json
{
  "192.168.1.1": { "name": "Home-Router", "type": "network" },
  "192.168.1.50": { "name": "NAS", "type": "storage" }
}
```

## Programmatic access

```python
from netsweep.config import get_config, get_config_manager, clamp_threads

cfg = get_config()
print(cfg.scan.timeout, cfg.security.max_scan_targets)

mgr = get_config_manager()
mgr.config.scan.max_workers = 30
mgr.save_config()

workers = clamp_threads(10_000)  # capped by max_threads
```

## Validation

```bash
python -m netsweep.cli.config_cmd --validate
```

Checks positive timeouts/workers, port range format, export format, and security floors (and `max_workers <= max_threads`).

## Notes

- **Singleton:** `get_config_manager()` caches the first instance; pass a custom path only on first call in a process.  
- **CLI overrides:** Explicit flags on `netsweep-lan` / `netsweep-host` override defaults for that run.  
- **Do not** set `max_concurrent_connections` extremely high without raising `ulimit -n`.  

Next: [Library API](library-api.md) · [Security](security.md).

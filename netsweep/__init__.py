"""NetSweep — professional network discovery and host scanning toolkit."""
from netsweep.__version__ import __version__, __version_info__

__all__ = [
    "__version__",
    "__version_info__",
    "get_config",
    "get_config_manager",
    "NetworkScanner",
    "DeviceInfo",
    "PortScanner",
    "ServiceDetector",
]


def __getattr__(name: str):
    # Lazy exports to keep import light
    if name in ("get_config", "get_config_manager"):
        from netsweep.config import get_config, get_config_manager
        return {"get_config": get_config, "get_config_manager": get_config_manager}[name]
    if name in ("NetworkScanner", "DeviceInfo", "PortScanner", "ServiceDetector"):
        from netsweep import scan as _scan
        return getattr(_scan, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

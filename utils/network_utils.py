"""Shim for network utils with historical get_local_ip() -> str contract."""
from importlib import import_module
import sys
import types

_impl = import_module("netsweep.net.interfaces")

# Build a module view that preserves get_local_ip as string-fallback alias
mod = types.ModuleType(__name__)
mod.__dict__.update({k: getattr(_impl, k) for k in dir(_impl) if not k.startswith("__")})
mod.get_local_ip = _impl.get_local_ip_str
mod.get_local_ip_str = _impl.get_local_ip_str
mod._trace_route = _impl._trace_route
sys.modules[__name__] = mod

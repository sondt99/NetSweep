"""Shim: re-exports netsweep.data.ports (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.data.ports")
sys.modules[__name__] = _impl

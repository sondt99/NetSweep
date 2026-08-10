"""Shim: re-exports netsweep.scan.ports (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.scan.ports")
sys.modules[__name__] = _impl

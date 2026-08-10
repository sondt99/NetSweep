"""Shim: re-exports netsweep.scan.service (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.scan.service")
sys.modules[__name__] = _impl

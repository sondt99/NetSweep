"""Shim: re-exports netsweep.scan.device (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.scan.device")
sys.modules[__name__] = _impl

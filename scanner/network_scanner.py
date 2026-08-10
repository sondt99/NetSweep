"""Shim: re-exports netsweep.scan.network (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.scan.network")
sys.modules[__name__] = _impl

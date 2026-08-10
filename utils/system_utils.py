"""Shim: re-exports netsweep.net.interfaces (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.net.interfaces")
sys.modules[__name__] = _impl

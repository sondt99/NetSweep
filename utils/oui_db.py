"""Shim: re-exports netsweep.data.oui (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.data.oui")
sys.modules[__name__] = _impl

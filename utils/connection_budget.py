"""Shim: re-exports netsweep.net.budget (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.net.budget")
sys.modules[__name__] = _impl

"""Shim: re-exports netsweep.logging.errors (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.logging.errors")
sys.modules[__name__] = _impl

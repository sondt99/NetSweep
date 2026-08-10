"""Shim: re-exports netsweep.cli.menu (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.cli.menu")
sys.modules[__name__] = _impl

if __name__ == "__main__":
    _impl.main()

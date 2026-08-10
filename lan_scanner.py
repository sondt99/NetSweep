"""Shim: re-exports netsweep.cli.lan (deprecated flat import path)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.cli.lan")
sys.modules[__name__] = _impl

if __name__ == "__main__":
    _impl.main()

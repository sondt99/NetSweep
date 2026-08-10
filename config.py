"""Shim: netsweep.config (deprecated flat import)."""
from importlib import import_module
import sys

_impl = import_module("netsweep.config")
# config package is a namespace package-like; expose manager + models attrs
sys.modules[__name__] = _impl

if __name__ == "__main__":
    from netsweep.cli.config_cmd import main
    main()

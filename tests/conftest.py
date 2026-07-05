import sys
from pathlib import Path

import pytest

# Ensure the project root is importable regardless of how pytest is invoked,
# since tests/ has no __init__.py and pytest's rootdir insertion would
# otherwise only add tests/ itself to sys.path.
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import utils.error_handler as error_handler_module  # noqa: E402 (needs sys.path set up above)


@pytest.fixture(autouse=True)
def isolated_error_handler(tmp_path, monkeypatch):
    """Point the module-level ErrorHandler singleton at a throwaway log file
    for every test, so nothing under test/ ever writes to the real
    logs/netsweep.log (get_error_handler(), log_info(), log_warning(), and the
    @handle_errors decorator all read this same global)."""
    monkeypatch.setattr(
        error_handler_module, "_error_handler",
        error_handler_module.ErrorHandler(log_file=str(tmp_path / "test.log")),
    )

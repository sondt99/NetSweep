"""Process-wide concurrent connection budget for NetSweep scanners.

Prevents FD exhaustion when many hosts open many non-blocking sockets at once.
"""

from __future__ import annotations

import threading
from typing import Optional

from config import get_config

_lock = threading.Lock()
_semaphore: Optional[threading.BoundedSemaphore] = None
_limit: Optional[int] = None


def get_connection_semaphore() -> threading.BoundedSemaphore:
    """Return a process-wide semaphore capped at max_concurrent_connections."""
    global _semaphore, _limit
    cfg_limit = max(1, int(get_config().security.max_concurrent_connections))
    with _lock:
        if _semaphore is None or _limit != cfg_limit:
            _limit = cfg_limit
            _semaphore = threading.BoundedSemaphore(cfg_limit)
        return _semaphore


def reset_connection_budget_for_tests() -> None:
    """Reset singleton (tests only)."""
    global _semaphore, _limit
    with _lock:
        _semaphore = None
        _limit = None

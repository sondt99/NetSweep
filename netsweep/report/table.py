"""CLI table presentation helpers."""
from __future__ import annotations

from typing import Any, Dict, List

from tabulate import tabulate


def format_device_table(results: List[Dict[str, Any]]) -> str:
    headers = ["IP", "MAC", "Vendor", "Device Type", "Open Ports"]
    table_data = [
        [r["ip"], r["mac"], r["vendor"], r["type"], r["ports"]] for r in results
    ]
    return tabulate(table_data, headers=headers, tablefmt="grid")

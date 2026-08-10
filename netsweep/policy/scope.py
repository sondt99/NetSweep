"""Scan scope and confirmation policy shared by LAN and host pipelines."""
from __future__ import annotations

import ipaddress
import sys
from typing import Union

from netsweep.config import get_config


def enforce_lan_scope(
    network: Union[ipaddress.IPv4Network, str],
    total_hosts: int,
    *,
    assume_yes: bool = False,
) -> None:
    """Raise ValueError or SystemExit if the LAN scope is not allowed."""
    cfg = get_config().security
    max_targets = max(1, int(cfg.max_scan_targets))
    if total_hosts > max_targets:
        raise ValueError(
            f"Network has {total_hosts} hosts which exceeds max_scan_targets={max_targets}. "
            f"Reduce the CIDR or raise security.max_scan_targets in ~/.netsweep/config.json."
        )
    net = network if isinstance(network, ipaddress.IPv4Network) else ipaddress.ip_network(network, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 networks are supported in this release")
    if cfg.require_user_confirmation and not assume_yes:
        needs_confirm = total_hosts > 256 or not (net.is_private or net.is_loopback)
        if needs_confirm:
            print(
                f"\n[!] About to scan {total_hosts} addresses on {net}. "
                "Only proceed if authorized."
            )
            ans = input("Continue? (y/N): ").strip().lower()
            if ans != "y":
                raise SystemExit("Scan aborted by user.")


def enforce_host_scope(ip: str, port_count: int, *, assume_yes: bool = False) -> None:
    """Confirm large port ranges / non-private hosts when required."""
    cfg = get_config()
    if assume_yes or not cfg.security.require_user_confirmation:
        return
    try:
        addr = ipaddress.ip_address(ip)
        is_private = addr.is_private or addr.is_loopback
    except ValueError:
        is_private = False
    if not is_private and not getattr(cfg.security, "allow_public_targets", False):
        ans = input(
            f"[!] Target {ip} is not a private address. Only scan systems you own or "
            f"are authorized to test. Continue? (y/N): "
        ).strip().lower()
        if ans != "y":
            print("Aborted.")
            sys.exit(0)
    if port_count > 5000:
        ans = input(f"[!] About to scan {port_count} ports. Continue? (y/N): ").strip().lower()
        if ans != "y":
            print("Aborted.")
            sys.exit(0)

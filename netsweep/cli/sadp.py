#!/usr/bin/env python3
"""Hikvision SADP discovery - find cameras and device info on LAN.

Experimental helper. Only use on networks you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import socket
import time
from typing import List, Optional, Tuple

SADP_PORT = 37020
DEFAULT_PROBE = bytes([0x21, 0x02, 0x01, 0x00] + [0] * 20)


def discover_sadp(
    broadcast: str = "255.255.255.255",
    extra_targets: Optional[List[str]] = None,
    timeout: float = 5.0,
    port: int = SADP_PORT,
) -> List[Tuple[tuple, bytes]]:
    """Send SADP probe and collect responses.

    Returns list of (addr, data) tuples.
    """
    results: List[Tuple[tuple, bytes]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(min(1.0, timeout))

        sock.sendto(DEFAULT_PROBE, (broadcast, port))
        for target in extra_targets or []:
            sock.sendto(DEFAULT_PROBE, (target, port))

        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                results.append((addr, data))
            except socket.timeout:
                continue
            except OSError:
                break
    finally:
        sock.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Hikvision SADP LAN discovery (authorized use only)")
    parser.add_argument("--broadcast", default="255.255.255.255", help="Broadcast address")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Optional unicast target (repeatable); no hardcoded LAN IPs",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Listen timeout seconds")
    args = parser.parse_args()

    print("Waiting for SADP responses...")
    responses = discover_sadp(
        broadcast=args.broadcast,
        extra_targets=args.target,
        timeout=args.timeout,
    )
    for addr, data in responses:
        print(f"\nFrom {addr}: {len(data)} bytes")
        x = data.find(b"<?xml")
        if x >= 0:
            # Print XML but avoid dumping unbounded binary
            print(data[x : x + 8192].decode(errors="replace"))
        else:
            print(data[:200].hex())
    print(f"Done. ({len(responses)} response(s))")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""netwatch: lightweight TCP port scanner using Python's standard library."""

from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Sequence

DEFAULT_PORTS = list(range(1, 1025))
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    587: "submission",
}


@dataclass(frozen=True)
class PortStatus:
    ip: str
    port: int
    open: bool
    service: str | None
    latency_ms: float | None


def parse_ports(port_spec: str | None) -> List[int]:
    """Parse a comma-separated port specification into a sorted, unique list.

    Supported formats include single ports ("80"), ranges ("80-90"), or
    comma-separated combinations ("22,80-82,443"). Defaults to 1-1024 when
    ``port_spec`` is ``None``.
    """

    if port_spec is None:
        return DEFAULT_PORTS

    ports: set[int] = set()
    for part in port_spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_str, end_str = part.split('-', maxsplit=1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:  # pragma: no cover - defensive guard
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}") from exc
            if start < 1 or end > 65535 or start > end:
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}") from exc
            if port < 1 or port > 65535:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
            ports.add(port)
    if not ports:
        raise argparse.ArgumentTypeError("No valid ports specified")
    return sorted(ports)


def expand_targets(target_spec: str) -> List[str]:
    """Expand a target specification into a list of IP strings.

    Accepted inputs:
    * Single IP (IPv4 or IPv6)
    * CIDR (e.g., 192.168.1.0/30)
    * Explicit range with a dash (e.g., 10.0.0.1-10.0.0.5)
    """

    target_spec = target_spec.strip()
    if not target_spec:
        raise argparse.ArgumentTypeError("Target cannot be empty")

    if '-' in target_spec and '/' not in target_spec:
        start_str, end_str = target_spec.split('-', maxsplit=1)
        start_ip = ipaddress.ip_address(start_str.strip())
        end_ip = ipaddress.ip_address(end_str.strip())
        if start_ip.version != end_ip.version:
            raise argparse.ArgumentTypeError("Start and end IP versions must match")
        if int(end_ip) < int(start_ip):
            raise argparse.ArgumentTypeError("IP range end must not precede start")
        return [str(ipaddress.ip_address(addr)) for addr in range(int(start_ip), int(end_ip) + 1)]

    try:
        network = ipaddress.ip_network(target_spec, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid target: {target_spec}") from exc

    return [str(ip) for ip in network.hosts()] or [str(network.network_address)]


def detect_service(port: int) -> str | None:
    return COMMON_SERVICES.get(port)


def scan_port(ip: str, port: int, timeout: float) -> PortStatus:
    """Attempt to TCP connect to a port and return its status."""

    start = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            latency_ms: float | None = (time.monotonic() - start) * 1000
            return PortStatus(ip=ip, port=port, open=True, service=detect_service(port), latency_ms=latency_ms)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return PortStatus(ip=ip, port=port, open=False, service=None, latency_ms=None)


def worker(ip: str, ports: Sequence[int], timeout: float, result_queue: "queue.Queue[PortStatus]") -> None:
    for port in ports:
        result_queue.put(scan_port(ip, port, timeout))


def run_scan(targets: Iterable[str], ports: Sequence[int], timeout: float, threads: int) -> List[PortStatus]:
    if timeout <= 0:
        raise ValueError("Timeout must be positive")
    if threads < 1:
        raise ValueError("Threads must be at least 1")

    results: list[PortStatus] = []
    result_queue: "queue.Queue[PortStatus]" = queue.Queue()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_target = {
            executor.submit(worker, ip, ports, timeout, result_queue): ip for ip in targets
        }
        for future in as_completed(future_to_target):
            try:
                future.result()
            except Exception as exc:  # pragma: no cover - defensive guard
                ip = future_to_target[future]
                print(f"[!] Worker for {ip} failed: {exc}", file=sys.stderr)
    while not result_queue.empty():
        results.append(result_queue.get())

    results.sort(key=lambda r: (r.ip, r.port))
    return results


def format_text(results: Sequence[PortStatus]) -> str:
    lines: list[str] = []
    for result in results:
        status = "open" if result.open else "closed"
        service = f" ({result.service})" if result.service else ""
        latency = f" [{result.latency_ms:.1f} ms]" if result.latency_ms is not None else ""
        lines.append(f"{result.ip}:{result.port} {status}{service}{latency}")
    return "\n".join(lines)


def format_json(results: Sequence[PortStatus]) -> str:
    payload = [
        {
            "ip": r.ip,
            "port": r.port,
            "open": r.open,
            "service": r.service,
            "latency_ms": r.latency_ms,
        }
        for r in results
    ]
    return json.dumps(payload, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="netwatch: simple TCP port scanner")
    parser.add_argument("target", help="Target IP, CIDR, or range (e.g., 10.0.0.1-10.0.0.5)")
    parser.add_argument(
        "-p",
        "--ports",
        help="Ports to scan (e.g., 22,80-90). Defaults to 1-1024.",
        type=parse_ports,
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument(
        "--threads",
        type=int,
        default=64,
        help="Number of worker threads (default: 64)",
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        targets = expand_targets(args.target)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    try:
        results = run_scan(targets, args.ports or DEFAULT_PORTS, timeout=args.timeout, threads=args.threads)
    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        print(format_json(results))
    else:
        print(format_text(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())

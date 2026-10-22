"""Conservative TCP connect checks restricted to validated loopback scope."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum

from netprobe.scope import ScopeError, ValidatedScope, parse_target

MAX_CONCURRENCY = 16
MAX_PORTS_PER_SCAN = 64
DEFAULT_TIMEOUT_SECONDS = 0.75

PORT_PROFILES: dict[str, tuple[int, ...]] = {
    "common": (21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 5432, 8080, 8443),
    "web": (80, 443, 8000, 8080, 8443),
}


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: PortState
    checked_at: str
    detail: str

    def as_dict(self) -> dict[str, str | int]:
        return asdict(self) | {"state": self.state.value}


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse comma-separated ports and inclusive ranges, with a strict size bound."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("ports must be a non-empty comma-separated list")
    ports: set[int] = set()
    for part in value.split(","):
        token = part.strip()
        if not token:
            raise ValueError("port list contains an empty item")
        if "-" in token:
            pieces = token.split("-")
            if len(pieces) != 2 or not all(piece.isdecimal() for piece in pieces):
                raise ValueError(f"invalid port range: {token!r}")
            start, end = (int(piece) for piece in pieces)
            if start > end:
                raise ValueError(f"port range start exceeds end: {token!r}")
            if end - start + 1 > MAX_PORTS_PER_SCAN:
                raise ValueError(f"a scan is limited to {MAX_PORTS_PER_SCAN} unique ports")
            ports.update(range(start, end + 1))
        elif token.isdecimal():
            ports.add(int(token))
        else:
            raise ValueError(f"invalid port: {token!r}")
        if len(ports) > MAX_PORTS_PER_SCAN:
            raise ValueError(f"a scan is limited to {MAX_PORTS_PER_SCAN} unique ports")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return tuple(sorted(ports))


def get_ports(*, profile: str | None = None, ports: str | None = None) -> tuple[int, ...]:
    """Resolve a named profile or explicit port selection."""
    if (profile is None) == (ports is None):
        raise ValueError("specify exactly one of profile or ports")
    if profile is not None:
        try:
            return PORT_PROFILES[profile]
        except KeyError as exc:
            raise ValueError(f"unknown port profile: {profile}") from exc
    if ports is None:
        raise ValueError("ports selection is missing")
    return parse_ports(ports)


def validate_scan_request(
    scope: ValidatedScope,
    target: str,
    ports: tuple[int, ...],
    *,
    concurrency: int = 8,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Validate every scan constraint without opening a network connection."""
    candidate = parse_target(target)
    if candidate.network is None and candidate.hostname != "localhost":
        raise ScopeError("Only localhost and literal loopback IP addresses can be scanned")
    if candidate.network is not None and candidate.network.num_addresses != 1:
        raise ScopeError("TCP scan accepts one host at a time, not a network range")
    if not scope.permits(target):
        raise ScopeError(f"Target {target!r} is outside the authorized scope or excluded")
    if not ports or len(ports) > MAX_PORTS_PER_SCAN:
        raise ValueError(f"select between 1 and {MAX_PORTS_PER_SCAN} ports")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise ValueError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not 0 < timeout <= 5:
        raise ValueError("timeout must be greater than 0 and no more than 5 seconds")

    if candidate.hostname == "localhost":
        # Deliberately pin localhost to IPv4 loopback rather than invoking DNS resolution.
        return "127.0.0.1"
    if candidate.network is None:
        raise ScopeError("Target must be localhost or a literal loopback IP")
    connect_host = str(candidate.network.network_address)
    address = ipaddress.ip_address(connect_host)
    if not address.is_loopback:
        raise ScopeError("Only loopback addresses can be scanned")
    return connect_host


async def _check_one(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> PortResult:
    checked_at = datetime.now(UTC).isoformat()
    async with semaphore:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port), timeout=timeout
            )
        except ConnectionRefusedError:
            return PortResult(host, port, PortState.CLOSED, checked_at, "connection refused")
        except TimeoutError:
            return PortResult(host, port, PortState.UNKNOWN, checked_at, "connection timed out")
        except OSError as exc:
            # OS-level network errors are ambiguous (filtered, unreachable, or local limits).
            return PortResult(host, port, PortState.UNKNOWN, checked_at, type(exc).__name__)
        else:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return PortResult(host, port, PortState.OPEN, checked_at, "TCP connection established")


async def scan_tcp(
    scope: ValidatedScope,
    target: str,
    ports: tuple[int, ...],
    *,
    concurrency: int = 8,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[PortResult]:
    """Check selected TCP ports after validating the target, before opening sockets."""
    connect_host = validate_scan_request(
        scope, target, ports, concurrency=concurrency, timeout=timeout
    )

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_check_one(connect_host, port, semaphore, timeout) for port in sorted(set(ports))]
    return await asyncio.gather(*tasks)

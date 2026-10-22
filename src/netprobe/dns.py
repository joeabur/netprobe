"""Explicit DNS lookups against a loopback DNS server in an isolated lab."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver

from netprobe.scope import ScopeError, ValidatedScope

DnsType = Literal["A", "AAAA", "MX", "NS", "TXT"]
_ALLOWED_TYPES = {"A", "AAAA", "MX", "NS", "TXT"}


@dataclass(frozen=True)
class DnsObservation:
    server: str
    name: str
    record_type: str
    observed_at: str
    status: str
    answers: tuple[str, ...]
    detail: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def validate_dns_request(scope: ValidatedScope, server: str, name: str, record_type: str) -> str:
    """Require an explicitly scoped literal loopback DNS server and bounded lab name."""
    try:
        server_ip = ipaddress.ip_address(server)
    except ValueError as exc:
        raise ScopeError("DNS server must be a literal loopback IP address") from exc
    if not server_ip.is_loopback or not scope.permits(server):
        raise ScopeError("DNS server must be explicitly authorized and loopback-only")
    if not isinstance(name, str) or not name or len(name) > 253 or name != name.strip():
        raise ValueError("DNS name must be a non-empty hostname of at most 253 characters")
    normalized = name.rstrip(".").lower()
    if normalized != "localhost" and not normalized.endswith(".test"):
        raise ValueError("DNS queries are limited to localhost and reserved .test names")
    try:
        parsed = dns.name.from_text(
            name, origin=dns.name.root, idna_codec=dns.name.IDNA_2008
        ).canonicalize()
    except (dns.name.NameTooLong, dns.name.LabelTooLong, UnicodeError, ValueError) as exc:
        raise ValueError("invalid DNS name") from exc
    if record_type not in _ALLOWED_TYPES:
        raise ValueError(f"unsupported record type {record_type!r}")
    return parsed.to_text()


async def query_dns(
    scope: ValidatedScope,
    server: str,
    name: str,
    record_type: DnsType,
    *,
    timeout: float = 2.0,
) -> DnsObservation:
    """Issue exactly one bounded DNS query to the selected local DNS server."""
    normalized_name = validate_dns_request(scope, server, name, record_type)
    if not 0 < timeout <= 3:
        raise ValueError("DNS timeout must be greater than 0 and at most 3 seconds")
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.port = 53
    resolver.timeout = timeout
    resolver.lifetime = timeout
    observed_at = datetime.now(UTC).isoformat()
    try:
        answer = await resolver.resolve(
            normalized_name,
            record_type,
            lifetime=timeout,
            search=False,
            raise_on_no_answer=False,
        )
    except dns.resolver.NXDOMAIN:
        return DnsObservation(
            server, normalized_name, record_type, observed_at, "nxdomain", (), "name does not exist"
        )
    except dns.resolver.NoNameservers:
        return DnsObservation(
            server,
            normalized_name,
            record_type,
            observed_at,
            "unavailable",
            (),
            "no usable DNS response",
        )
    except (dns.exception.Timeout, TimeoutError):
        return DnsObservation(
            server, normalized_name, record_type, observed_at, "timeout", (), "DNS query timed out"
        )
    except dns.exception.DNSException as exc:
        return DnsObservation(
            server, normalized_name, record_type, observed_at, "error", (), type(exc).__name__
        )
    if answer.rrset is None:
        return DnsObservation(
            server,
            normalized_name,
            record_type,
            observed_at,
            "no-answer",
            (),
            "valid response contained no requested records",
        )
    records = tuple(str(record)[:512] for record in answer)
    return DnsObservation(
        server,
        normalized_name,
        record_type,
        observed_at,
        "answered",
        records,
        "single explicit query; no zone transfer or brute force",
    )

"""Strict scope parsing. This release intentionally accepts loopback targets only."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ScopeError(ValueError):
    """Raised when scope is malformed or violates the local-only boundary."""


@dataclass(frozen=True)
class Target:
    original: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    hostname: str | None = None

    def contains(self, other: Target) -> bool:
        if self.hostname is not None or other.hostname is not None:
            return self.hostname is not None and self.hostname == other.hostname
        if self.network is None or other.network is None:
            raise ScopeError("Invalid target representation")
        if isinstance(self.network, ipaddress.IPv4Network):
            return isinstance(other.network, ipaddress.IPv4Network) and other.network.subnet_of(
                self.network
            )
        return isinstance(other.network, ipaddress.IPv6Network) and other.network.subnet_of(
            self.network
        )

    def overlaps(self, other: Target) -> bool:
        if self.hostname is not None or other.hostname is not None:
            return self.hostname is not None and self.hostname == other.hostname
        if self.network is None or other.network is None:
            raise ScopeError("Invalid target representation")
        if isinstance(self.network, ipaddress.IPv4Network):
            return isinstance(other.network, ipaddress.IPv4Network) and self.network.overlaps(
                other.network
            )
        return isinstance(other.network, ipaddress.IPv6Network) and self.network.overlaps(
            other.network
        )


@dataclass(frozen=True)
class ValidatedScope:
    authorized_targets: tuple[Target, ...]
    exclusions: tuple[Target, ...]
    authorization_confirmed: bool

    def permits(self, raw_target: str) -> bool:
        candidate = parse_target(raw_target)
        return (
            is_local_target(candidate)
            and any(scope.contains(candidate) for scope in self.authorized_targets)
            and not any(exclusion.overlaps(candidate) for exclusion in self.exclusions)
        )


def parse_target(value: str) -> Target:
    """Parse a single IP, strict CIDR, or the explicitly supported local name."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ScopeError("Target must be a non-empty, whitespace-free string")
    if value.lower() == "localhost":
        return Target(original=value, network=None, hostname="localhost")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=True)
        else:
            address = ipaddress.ip_address(value)
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=True)
    except ValueError as exc:
        raise ScopeError(f"Invalid or unsupported target {value!r}") from exc
    return Target(original=value, network=network)


def is_local_target(target: Target) -> bool:
    """Only accept the loopback address space; never resolve arbitrary hostnames."""
    if target.hostname is not None:
        return target.hostname == "localhost"
    if target.network is None:
        return False
    if isinstance(target.network, ipaddress.IPv4Network):
        return target.network.subnet_of(ipaddress.IPv4Network("127.0.0.0/8"))
    return target.network.subnet_of(ipaddress.IPv6Network("::1/128"))


def validate_scope_data(data: Any) -> ValidatedScope:
    if not isinstance(data, dict):
        raise ScopeError("Scope document must be a YAML mapping")
    allowed_keys = {"authorized_targets", "exclusions", "authorization_confirmed"}
    unknown = set(data) - allowed_keys
    if unknown:
        raise ScopeError(f"Unsupported scope key(s): {', '.join(sorted(map(str, unknown)))}")
    targets = data.get("authorized_targets")
    exclusions = data.get("exclusions", [])
    confirmed = data.get("authorization_confirmed")
    if not isinstance(targets, list) or not targets:
        raise ScopeError("authorized_targets must be a non-empty list")
    if not isinstance(exclusions, list):
        raise ScopeError("exclusions must be a list")
    if confirmed is not True:
        raise ScopeError("authorization_confirmed must be true")

    parsed_targets = tuple(parse_target(item) for item in targets)
    parsed_exclusions = tuple(parse_target(item) for item in exclusions)
    if any(not is_local_target(target) for target in (*parsed_targets, *parsed_exclusions)):
        raise ScopeError(
            "This build is loopback-only: targets must be localhost or in loopback IP ranges"
        )
    for exclusion in parsed_exclusions:
        if not any(target.contains(exclusion) for target in parsed_targets):
            raise ScopeError(f"Exclusion {exclusion.original!r} is outside authorized scope")
    return ValidatedScope(parsed_targets, parsed_exclusions, confirmed)


def load_scope(path: str | Path) -> ValidatedScope:
    scope_path = Path(path)
    try:
        raw = scope_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScopeError(f"Cannot read scope file: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ScopeError(f"Invalid YAML scope file: {exc}") from exc
    return validate_scope_data(data)

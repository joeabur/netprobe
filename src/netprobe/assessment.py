"""Single-host loopback assessment orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from netprobe.checks.http import run_checks as run_http_checks
from netprobe.checks.tls import check_tls_certificate
from netprobe.enumeration.service import Protocol, ServiceObservation, inspect_service
from netprobe.models import Finding
from netprobe.scanner.tcp import PortResult, scan_tcp
from netprobe.scope import ValidatedScope


@dataclass(frozen=True)
class AssessmentResult:
    target: str
    port_results: list[PortResult]
    observations: list[ServiceObservation]
    findings: list[Finding]
    limitations: list[str]


def _findings_for(observation: ServiceObservation) -> list[Finding]:
    return [*run_http_checks(observation), *check_tls_certificate(observation)]


async def run_assessment(
    scope: ValidatedScope,
    target: str,
    ports: tuple[int, ...],
    *,
    concurrency: int = 8,
    timeout: float = 1.0,
    protocol_overrides: dict[int, Protocol] | None = None,
) -> AssessmentResult:
    """Scan selected ports on one permitted loopback host and inspect only open ports."""
    port_results = await scan_tcp(scope, target, ports, concurrency=concurrency, timeout=timeout)
    open_ports = [result.port for result in port_results if result.state.value == "open"]
    semaphore = asyncio.Semaphore(min(concurrency, 8))

    async def inspect(port: int) -> ServiceObservation:
        async with semaphore:
            return await inspect_service(
                scope,
                target,
                port,
                protocol=(protocol_overrides or {}).get(port, "auto"),
                timeout=min(timeout, 5.0),
            )

    observations = await asyncio.gather(*(inspect(port) for port in open_ports))
    findings = [finding for observation in observations for finding in _findings_for(observation)]
    limitations = [
        "Loopback-only assessment of one explicitly scoped host.",
        "Port checks use TCP connect; unknown is not treated as closed.",
        "Service observations are limited to safe banners, HTTP HEAD, and TLS leaf metadata.",
        "No DNS discovery, authentication, exploit validation, or trust-chain checks.",
        "Findings are observations or leads and require human validation.",
    ]
    return AssessmentResult(target, port_results, observations, findings, limitations)

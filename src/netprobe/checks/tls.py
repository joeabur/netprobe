"""Validation-required TLS certificate observations from local service handshakes."""

from __future__ import annotations

from netprobe.enumeration.service import ServiceObservation
from netprobe.models import Confidence, Finding, FindingStatus, Severity


def check_tls_certificate(observation: ServiceObservation) -> list[Finding]:
    """Create cautious findings for expired or IP-mismatched observed certificates."""
    if observation.protocol != "https" or observation.status != "observed":
        return []
    details = observation.details
    if details.get("certificate_present") is not True:
        return []
    findings: list[Finding] = []
    if details.get("certificate_expired") is True:
        findings.append(
            Finding(
                check_id="TLS-CERT-EXPIRED-001",
                title="TLS certificate appears expired",
                description=(
                    "The presented certificate's notAfter date is earlier "
                    "than the local check time."
                ),
                host=observation.host,
                port=observation.port,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=f"Certificate notAfter: {details.get('certificate_not_after', 'unknown')}",
                remediation="Renew and deploy a certificate with a current validity period.",
                verification_limitations=(
                    "This evaluates the leaf certificate date from one handshake only; verify "
                    "system clock, deployment, chain, and client-facing hostname independently."
                ),
                status=FindingStatus.REQUIRES_VALIDATION,
                exposure_factor=0.25,
                evidence_quality=0.9,
            )
        )
    if details.get("certificate_target_ip_match") is False:
        san_value = details.get("certificate_san", "")
        findings.append(
            Finding(
                check_id="TLS-CERT-IP-SAN-001",
                title="TLS certificate does not list the connected loopback IP",
                description=(
                    "The certificate Subject Alternative Name extension did not contain the "
                    "literal loopback IP used for this connection. This does not assess DNS names."
                ),
                host=observation.host,
                port=observation.port,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=f"Connected IP: {observation.host}; SAN: {san_value}",
                remediation=(
                    "Validate the service using its intended DNS name and issue a certificate "
                    "whose SAN matches that client-facing name; do not infer a DNS mismatch "
                    "from IP use."
                ),
                verification_limitations=(
                    "Only literal IP SAN matching is checked. DNS hostname matching and "
                    "trust-chain validation are not performed. This is common for local test "
                    "certificates."
                ),
                status=FindingStatus.REQUIRES_VALIDATION,
                exposure_factor=0.1,
                evidence_quality=0.8,
            )
        )
    return findings

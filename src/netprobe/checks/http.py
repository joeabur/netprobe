"""HTTP configuration checks based solely on bounded observed response headers."""

from __future__ import annotations

from typing import Protocol

from netprobe.enumeration.service import ServiceObservation
from netprobe.models import Confidence, Finding, FindingStatus, Severity


class ObservationCheck(Protocol):
    """A plugin evaluates one service observation and returns zero or more findings."""

    check_id: str

    def __call__(self, observation: ServiceObservation) -> list[Finding]: ...


class MissingHttpSecurityHeaders:
    """Report selected absent headers as a validation lead, not a proven vulnerability."""

    check_id = "HTTP-SECURITY-HEADERS-001"

    def __call__(self, observation: ServiceObservation) -> list[Finding]:
        if observation.protocol != "http" or observation.status != "observed":
            return []
        details = observation.details
        if "status_line" not in details or "parse_error" in details:
            return []

        missing: list[str] = []
        csp = details.get("content-security-policy")
        frame_options = details.get("x-frame-options")
        if not csp and not frame_options:
            missing.append("Content-Security-Policy or X-Frame-Options")
        if not details.get("x-content-type-options"):
            missing.append("X-Content-Type-Options")
        if not details.get("referrer-policy"):
            missing.append("Referrer-Policy")
        if not missing:
            return []

        return [
            Finding(
                check_id=self.check_id,
                title="Selected HTTP security headers are absent",
                description=(
                    "The observed HTTP HEAD response omitted one or more selected browser "
                    "security headers. Applicability depends on the content served and client "
                    "behavior; this is a configuration lead, not proof of exploitability."
                ),
                host=observation.host,
                port=observation.port,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=f"Missing from response: {', '.join(missing)}",
                remediation=(
                    "Review whether this service serves browser-rendered content. Where relevant, "
                    "configure a restrictive Content-Security-Policy, X-Content-Type-Options: "
                    "nosniff, Referrer-Policy, and framing protections."
                ),
                verification_limitations=(
                    "Only one HEAD response was inspected. Header policy may vary by route, "
                    "method, content type, or client; verify with application owners."
                ),
                confirmed_misconfiguration=False,
                status=FindingStatus.REQUIRES_VALIDATION,
                exposure_factor=0.25,
                evidence_quality=0.8,
            )
        ]


class CookieSecurityAttributes:
    """Flag omitted cookie attributes while excluding cookie values from all output."""

    check_id = "HTTP-COOKIE-ATTRIBUTES-001"

    def __call__(self, observation: ServiceObservation) -> list[Finding]:
        details = observation.details
        if observation.protocol != "http" or observation.status != "observed":
            return []
        if details.get("cookies_observed") != "true":
            return []
        missing = [
            attribute
            for key, attribute in (
                ("cookies_missing_secure", "Secure"),
                ("cookies_missing_httponly", "HttpOnly"),
                ("cookies_missing_samesite", "SameSite"),
            )
            if details.get(key) == "true"
        ]
        if not missing:
            return []
        return [
            Finding(
                check_id=self.check_id,
                title="Observed cookie lacks security attributes",
                description=(
                    "At least one Set-Cookie response header lacked one or more common "
                    "security attributes. Cookie values are intentionally not retained."
                ),
                host=observation.host,
                port=observation.port,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=f"Missing attributes observed: {', '.join(missing)}",
                remediation=(
                    "Review cookie purpose and set Secure for HTTPS-only cookies, HttpOnly "
                    "where JavaScript access is unnecessary, and an appropriate SameSite policy."
                ),
                verification_limitations=(
                    "Only cookies returned by this single HEAD response were observed; other "
                    "routes may set different cookies. Applicability requires validation."
                ),
                confirmed_misconfiguration=False,
                status=FindingStatus.REQUIRES_VALIDATION,
                exposure_factor=0.25,
                evidence_quality=0.8,
            )
        ]


HTTP_CHECKS: tuple[ObservationCheck, ...] = (
    MissingHttpSecurityHeaders(),
    CookieSecurityAttributes(),
)


def run_checks(
    observation: ServiceObservation,
    checks: tuple[ObservationCheck, ...] = HTTP_CHECKS,
) -> list[Finding]:
    """Run registered plugins in deterministic order against an observation."""
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check(observation))
    return findings


def registered_check_ids(checks: tuple[ObservationCheck, ...] = HTTP_CHECKS) -> tuple[str, ...]:
    """Expose plugin identifiers for documentation and integration consumers."""
    return tuple(check.check_id for check in checks)

"""Validated domain models for local-lab assessment records."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    REQUIRES_VALIDATION = "requires_validation"


_SEVERITY_WEIGHT = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}
_CONFIDENCE_FACTOR = {
    Confidence.LOW: 0.5,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}


class Finding(BaseModel):
    """A finding, with a transparent local prioritization score (not CVSS)."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    check_id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    severity: Severity
    confidence: Confidence
    evidence: str = Field(default="", max_length=4000)
    remediation: str = Field(default="", max_length=4000)
    verification_limitations: str = Field(default="", max_length=2000)
    cve_references: list[str] = Field(default_factory=list)
    cwe_references: list[str] = Field(default_factory=list)
    confirmed_misconfiguration: bool = False
    status: FindingStatus = FindingStatus.OPEN
    exposure_factor: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=0.5, ge=0.0, le=1.0)
    cvss_score: None = None

    @property
    def priority_score(self) -> int:
        """Return a 0-100 prioritization score; this is explicitly not a CVSS score."""
        value = (
            _SEVERITY_WEIGHT[self.severity]
            * _CONFIDENCE_FACTOR[self.confidence]
            * (0.5 + self.exposure_factor / 2)
            * (0.5 + self.evidence_quality / 2)
        )
        return round(value)


class AssessmentMetadata(BaseModel):
    """Reproducibility metadata without secrets or credential fields."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    tool_name: str = "NetProbe"
    tool_version: str
    scope_file: str
    authorized_targets: list[str]
    exclusions: list[str] = Field(default_factory=list)
    authorization_confirmed: bool
    profile: str = "dry-run"
    limitations: list[str] = Field(default_factory=list)

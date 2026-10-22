from netprobe.models import Confidence, Finding, Severity


def test_finding_priority_is_bounded_and_not_cvss() -> None:
    finding = Finding(
        check_id="LOCAL-001",
        title="Test observation",
        description="Fixture finding",
        host="127.0.0.1",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence="unit-test evidence",
        exposure_factor=1.0,
        evidence_quality=1.0,
    )
    assert finding.priority_score == 70
    assert finding.cvss_score is None
    assert finding.model_dump(mode="json")["severity"] == "High"

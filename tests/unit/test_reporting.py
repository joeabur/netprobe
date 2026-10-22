import csv
import io
import json
from pathlib import Path

import pytest

from netprobe.reporting.render import render_report, write_report
from netprobe.storage.artifacts import (
    ArtifactError,
    latest_artifact,
    load_json_artifact,
    validate_artifact_name,
    write_json_artifact,
)


def artifact() -> dict:
    return {
        "schema_version": 1,
        "metadata": {
            "assessment_id": "assessment-test-1",
            "started_at": "2026-10-22T00:00:00+00:00",
            "completed_at": "2026-10-22T00:01:00+00:00",
            "tool_name": "NetProbe",
            "tool_version": "0.1.0",
            "profile": "check-http",
            "authorized_targets": ["127.0.0.1"],
            "exclusions": [],
            "limitations": ["single local HEAD response"],
        },
        "observations": [
            {
                "host": "127.0.0.1",
                "port": 8080,
                "protocol": "http",
                "status": "observed",
                "details": {"status_line": "HTTP/1.1 200 OK"},
            }
        ],
        "findings": [
            {
                "finding_id": "finding-1",
                "check_id": "HTTP-SECURITY-HEADERS-001",
                "title": "Missing <script>alert(1)</script>",
                "description": "Check <img src=x onerror=alert(1)>",
                "host": "127.0.0.1",
                "port": 8080,
                "severity": "Low",
                "confidence": "High",
                "priority_score": 16,
                "status": "requires_validation",
                "evidence": "Missing Referrer-Policy",
                "remediation": "Configure a policy",
                "verification_limitations": "Single response only",
            }
        ],
    }


def test_json_report_is_structured() -> None:
    rendered = json.loads(render_report(artifact(), "json"))
    assert rendered["metadata"]["assessment_id"] == "assessment-test-1"


def test_csv_report_contains_summary_observation_and_finding() -> None:
    rows = list(csv.DictReader(io.StringIO(render_report(artifact(), "csv"))))
    assert [row["record_type"] for row in rows] == ["assessment", "observation", "finding"]
    assert rows[0]["authorized_targets"] == "127.0.0.1"
    assert rows[-1]["title"] == "Missing <script>alert(1)</script>"


def test_csv_report_neutralizes_spreadsheet_formulas() -> None:
    document = artifact()
    document["findings"][0]["title"] = "=HYPERLINK('http://example.test')"
    rows = list(csv.DictReader(io.StringIO(render_report(document, "csv"))))
    assert rows[-1]["title"].startswith("'=")


def test_html_report_escapes_untrusted_fields() -> None:
    rendered = render_report(artifact(), "html")
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "<img src=x onerror=alert(1)>" not in rendered


def test_dns_observations_render_in_html_and_csv() -> None:
    document = artifact()
    document["metadata"]["profile"] = "dns-check"
    document["observations"] = [
        {
            "host": "127.0.0.1",
            "port": 53,
            "protocol": "dns",
            "status": "answered",
            "details": {
                "name": "lab.test.",
                "record_type": "A",
                "answers": ["127.0.0.2"],
            },
        }
    ]
    assert "lab.test." in render_report(document, "html")
    rows = list(csv.DictReader(io.StringIO(render_report(document, "csv"))))
    observation = next(row for row in rows if row["record_type"] == "observation")
    assert observation["observation_protocol"] == "dns"
    assert "127.0.0.2" in observation["evidence"]


def test_artifact_storage_is_exclusive_and_loads_schema(tmp_path: Path) -> None:
    path = write_json_artifact(tmp_path, "assessment-1", artifact())
    assert load_json_artifact(path)["metadata"]["assessment_id"] == "assessment-test-1"
    with pytest.raises(ArtifactError, match="already exists"):
        write_json_artifact(tmp_path, "assessment-1", artifact())


def test_artifact_name_rejects_traversal_and_absolute_paths() -> None:
    for name in ("../escape", "root/escape", "bad name", ""):
        with pytest.raises(ArtifactError):
            validate_artifact_name(name)


def test_latest_artifact_ignores_symlinks(tmp_path: Path) -> None:
    saved = write_json_artifact(tmp_path, "assessment-1", artifact())
    (tmp_path / "linked.json").symlink_to(saved.name)
    assert latest_artifact(tmp_path) == saved


def test_report_output_refuses_overwrite_and_validates_path(tmp_path: Path) -> None:
    output = write_report(tmp_path, "report-1", "html", "<p>ok</p>")
    assert output.read_text(encoding="utf-8") == "<p>ok</p>"
    with pytest.raises(ArtifactError, match="already exists"):
        write_report(tmp_path, "report-1", "html", "replacement")
    with pytest.raises(ArtifactError):
        write_report(tmp_path, "../outside", "html", "bad")


def test_explicit_overwrite_replaces_report(tmp_path: Path) -> None:
    output = write_report(tmp_path, "report-1", "json", "first")
    write_report(tmp_path, "report-1", "json", "second", overwrite=True)
    assert output.read_text(encoding="utf-8") == "second"

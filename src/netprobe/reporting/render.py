"""JSON, CSV, and escaped HTML reports for stored assessment artifacts."""

# Ruff E501 is disabled here because the literal HTML/Jinja template is easier to audit as markup.
# ruff: noqa: E501

from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment

from netprobe.storage.artifacts import ArtifactError, validate_artifact_name

ReportFormat = Literal["json", "csv", "html"]

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetProbe assessment {{ metadata.assessment_id }}</title>
  <style>
    body { font: 16px/1.5 system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color: #172033; }
    h1, h2 { color: #102a43; } table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }
    th, td { border: 1px solid #d5dee8; padding: .55rem; text-align: left; vertical-align: top; }
    th { background: #edf3f8; } .badge { font-weight: 700; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <h1>NetProbe Assessment Report</h1>
  <p><strong>Assessment:</strong> {{ metadata.assessment_id }}</p>
  <p><strong>Started:</strong> {{ metadata.started_at }} · <strong>Completed:</strong> {{ metadata.completed_at or "Incomplete" }}</p>
  <p><strong>Profile:</strong> {{ metadata.profile }} · <strong>Tool:</strong> {{ metadata.tool_name }} {{ metadata.tool_version }}</p>
  <section><h2>Executive summary</h2>
    <p>{{ findings|length }} finding(s) across {{ observations|length }} observation(s). Highest severity: {{ highest_severity }}.</p>
    <p>Scope is local-lab only. Findings require professional validation and are not proof of exploitability.</p>
  </section>
  <section><h2>Authorized scope and exclusions</h2>
    <p><strong>Targets:</strong> {{ metadata.authorized_targets|join(", ") }}</p>
    <p><strong>Exclusions:</strong> {{ metadata.exclusions|join(", ") if metadata.exclusions else "None" }}</p>
  </section>
  <section><h2>Severity distribution</h2>
    <ul>{% for severity, count in severity_counts.items() %}<li>{{ severity }}: {{ count }}</li>{% endfor %}</ul>
  </section>
  <section><h2>Observations</h2>
    <table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Status</th><th>Details</th></tr></thead>
    <tbody>{% for item in observations %}<tr><td>{{ item.host }}</td><td>{{ item.port }}</td><td>{{ item.protocol }}</td><td>{{ item.status }}</td><td><pre>{{ item.details|tojson(indent=2) }}</pre></td></tr>{% else %}<tr><td colspan="5">No observations recorded.</td></tr>{% endfor %}</tbody></table>
  </section>
  <section><h2>Technical findings and remediation</h2>
    {% for finding in findings %}<article><h3>{{ finding.title }}</h3>
      <p><span class="badge">{{ finding.severity }}</span> · {{ finding.confidence }} confidence · Priority {{ finding.priority_score }}/100 · {{ finding.host }}:{{ finding.port or "n/a" }}</p>
      <p>{{ finding.description }}</p><p><strong>Evidence:</strong> {{ finding.evidence }}</p>
      <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
      <p><strong>Limitations:</strong> {{ finding.verification_limitations }}</p>
    </article>{% else %}<p>No findings were recorded.</p>{% endfor %}
  </section>
  <section><h2>Limitations and prioritized remediation</h2>
    <ol>{% for finding in prioritized_findings %}<li>{{ finding.severity }} — {{ finding.title }}: {{ finding.remediation }}</li>{% else %}<li>No remediation items.</li>{% endfor %}</ol>
    <ul>{% for limitation in metadata.limitations %}<li>{{ limitation }}</li>{% endfor %}</ul>
  </section>
</body>
</html>
"""

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _normalize(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema_version") != 1:
        raise ArtifactError("unsupported assessment artifact schema")
    metadata = document.get("metadata")
    observations = document.get("observations")
    findings = document.get("findings")
    if (
        not isinstance(metadata, dict)
        or not isinstance(observations, list)
        or not isinstance(findings, list)
    ):
        raise ArtifactError("malformed assessment artifact fields")
    sanitized_findings: list[dict[str, Any]] = []
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        finding = dict(raw)
        severity = str(finding.get("severity", "Informational"))
        finding.setdefault("priority_score", 0)
        finding["severity"] = severity
        sanitized_findings.append(finding)
    counts = Counter(str(item.get("severity", "Informational")) for item in sanitized_findings)
    highest = (
        min(counts, key=lambda severity: _SEVERITY_ORDER.get(severity, 99)) if counts else "None"
    )
    return {
        "metadata": metadata,
        "observations": [item for item in observations if isinstance(item, dict)],
        "findings": sanitized_findings,
        "severity_counts": dict(
            sorted(counts.items(), key=lambda item: _SEVERITY_ORDER.get(item[0], 99))
        ),
        "highest_severity": highest,
        "prioritized_findings": sorted(
            sanitized_findings,
            key=lambda item: (
                _SEVERITY_ORDER.get(str(item.get("severity")), 99),
                -int(item.get("priority_score", 0)),
            ),
        ),
    }


def _csv_safe_row(row: dict[str, Any]) -> dict[str, Any]:
    """Neutralize spreadsheet formula prefixes in untrusted string cells."""
    safe: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            safe[key] = "'" + value
        else:
            safe[key] = value
    return safe


def render_report(document: dict[str, Any], report_format: ReportFormat) -> str:
    """Render an assessment artifact into the selected format."""
    data = _normalize(document)
    if report_format == "json":
        return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if report_format == "csv":
        output = io.StringIO(newline="")
        fieldnames = (
            "record_type",
            "assessment_id",
            "started_at",
            "completed_at",
            "tool_name",
            "tool_version",
            "profile",
            "authorized_targets",
            "exclusions",
            "severity_counts",
            "finding_id",
            "check_id",
            "title",
            "severity",
            "confidence",
            "priority_score",
            "host",
            "port",
            "status",
            "evidence",
            "remediation",
            "verification_limitations",
            "limitations",
            "observation_protocol",
            "observation_status",
        )
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        metadata = data["metadata"]
        common = {
            "assessment_id": metadata.get("assessment_id"),
            "started_at": metadata.get("started_at"),
            "completed_at": metadata.get("completed_at"),
            "tool_name": metadata.get("tool_name"),
            "tool_version": metadata.get("tool_version"),
            "profile": metadata.get("profile"),
            "authorized_targets": "; ".join(metadata.get("authorized_targets", [])),
            "exclusions": "; ".join(metadata.get("exclusions", [])),
            "severity_counts": json.dumps(data["severity_counts"], sort_keys=True),
            "limitations": "; ".join(metadata.get("limitations", [])),
        }
        writer.writerow(_csv_safe_row({"record_type": "assessment", **common}))
        for observation in data["observations"]:
            writer.writerow(
                _csv_safe_row(
                    {
                        "record_type": "observation",
                        **common,
                        "host": observation.get("host"),
                        "port": observation.get("port"),
                        "observation_protocol": observation.get("protocol"),
                        "observation_status": observation.get("status"),
                        "evidence": json.dumps(observation.get("details", {}), sort_keys=True),
                    }
                )
            )
        for finding in data["findings"]:
            writer.writerow(_csv_safe_row({"record_type": "finding", **common, **finding}))
        return output.getvalue()
    # Explicit True is essential here: from_string templates have no filename to inspect.
    environment = Environment(autoescape=True)
    template = environment.from_string(_HTML_TEMPLATE)
    return template.render(**data)


def write_report(
    directory: str | Path,
    name: str,
    report_format: ReportFormat,
    content: str,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a report with safe filename and no-overwrite-by-default behavior."""
    safe_name = validate_artifact_name(name)
    extension = {"json": ".json", "csv": ".csv", "html": ".html"}[report_format]
    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = output_dir / f"{safe_name}{extension}"
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ArtifactError(f"report already exists: {path}") from exc
    except OSError as exc:
        raise ArtifactError(f"cannot create report: {exc.strerror or exc}") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ArtifactError(f"cannot write report: {exc.strerror or exc}") from exc
    return path

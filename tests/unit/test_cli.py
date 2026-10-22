import json
from pathlib import Path

from netprobe.cli import EXIT_INPUT_ERROR, EXIT_OK, main

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_validate_scope_succeeds(capsys) -> None:
    result = main(["validate-scope", "--scope", str(FIXTURES / "valid_scope.yaml")])
    assert result == EXIT_OK
    assert '"valid": true' in capsys.readouterr().out


def test_dry_run_does_not_start_network_scan(capsys) -> None:
    result = main(["assess", "--scope", str(FIXTURES / "valid_scope.yaml"), "--dry-run"])
    assert result == EXIT_OK
    output = capsys.readouterr().out
    assert '"network_activity": false' in output
    assert "127.0.0.1" in output


def test_active_assessment_requires_single_target(capsys) -> None:
    result = main(["assess", "--scope", str(FIXTURES / "valid_scope.yaml")])
    assert result == EXIT_INPUT_ERROR
    assert "requires --target" in capsys.readouterr().err


def test_assess_dry_run_rejects_out_of_scope_target(capsys) -> None:
    result = main(
        [
            "assess",
            "--scope",
            str(FIXTURES / "valid_scope.yaml"),
            "--target",
            "192.0.2.4",
            "--dry-run",
        ]
    )
    assert result == EXIT_INPUT_ERROR
    assert "outside the authorized scope" in capsys.readouterr().err


def test_assess_dry_run_validates_request_without_network(capsys, monkeypatch) -> None:
    import asyncio

    def forbidden(*args, **kwargs):
        raise AssertionError("dry-run opened a socket")

    monkeypatch.setattr(asyncio, "open_connection", forbidden)
    result = main(
        [
            "assess",
            "--scope",
            str(FIXTURES / "valid_scope.yaml"),
            "--target",
            "127.0.0.1",
            "--ports",
            "80,443",
            "--dry-run",
        ]
    )
    assert result == EXIT_OK
    assert '"network_activity": false' in capsys.readouterr().out


def test_dns_check_dry_run_has_no_network_activity(capsys, monkeypatch) -> None:
    import asyncio

    def forbidden(*args, **kwargs):
        raise AssertionError("dry-run performed DNS activity")

    monkeypatch.setattr(asyncio, "get_running_loop", forbidden)
    result = main(
        [
            "dns-check",
            "--scope",
            str(FIXTURES / "valid_scope.yaml"),
            "--server",
            "127.0.0.1",
            "--name",
            "lab.test",
            "--dry-run",
        ]
    )
    assert result == EXIT_OK
    assert '"network_activity": false' in capsys.readouterr().out


def test_active_dns_check_saves_reproducible_artifact(tmp_path, capsys, monkeypatch) -> None:
    from datetime import UTC, datetime

    from netprobe.dns import DnsObservation

    result_observation = DnsObservation(
        server="127.0.0.1",
        name="lab.test.",
        record_type="A",
        observed_at=datetime.now(UTC).isoformat(),
        status="answered",
        answers=("127.0.0.2",),
        detail="single explicit test query",
    )

    def fake_run(awaitable):
        awaitable.close()
        return result_observation

    monkeypatch.setattr("netprobe.cli.asyncio.run", fake_run)
    artifact_dir = tmp_path / "dns-artifacts"
    result = main(
        [
            "dns-check",
            "--scope",
            str(FIXTURES / "valid_scope.yaml"),
            "--server",
            "127.0.0.1",
            "--name",
            "lab.test",
            "--type",
            "A",
            "--i-have-authorization",
            "--artifact-dir",
            str(artifact_dir),
        ]
    )
    assert result == EXIT_OK
    output = json.loads(capsys.readouterr().out)
    artifact_path = Path(output["assessment_artifact"])
    stored = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert stored["metadata"]["profile"] == "dns-check"
    assert stored["observations"][0]["details"]["answers"] == ["127.0.0.2"]
    assert stored["findings"] == []
    assert artifact_path.stat().st_mode & 0o777 == 0o600


def test_invalid_scope_returns_input_exit_code(capsys) -> None:
    path = FIXTURES / "invalid_scope.yaml"
    assert main(["validate-scope", "--scope", str(path)]) == EXIT_INPUT_ERROR
    assert "loopback-only" in capsys.readouterr().err


def test_report_cli_renders_latest_artifact(tmp_path, capsys) -> None:
    import json

    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    artifact = {
        "schema_version": 1,
        "metadata": {
            "assessment_id": "cli-assessment",
            "started_at": "2026-10-22T00:00:00+00:00",
            "completed_at": None,
            "tool_name": "NetProbe",
            "tool_version": "0.1.0",
            "profile": "test",
            "authorized_targets": ["127.0.0.1"],
            "exclusions": [],
            "limitations": [],
        },
        "observations": [],
        "findings": [],
    }
    from netprobe.storage.artifacts import write_json_artifact

    write_json_artifact(artifact_dir, "assessment", artifact)
    output_dir = tmp_path / "reports"
    assert (
        main(
            [
                "report",
                "--assessment",
                "latest",
                "--artifact-dir",
                str(artifact_dir),
                "--format",
                "html",
                "--output-dir",
                str(output_dir),
            ]
        )
        == EXIT_OK
    )
    output = json.loads(capsys.readouterr().out)
    assert output["format"] == "html"
    assert (output_dir / "cli-assessment.html").exists()


def test_check_http_saves_reproducible_artifact(tmp_path, capsys, monkeypatch) -> None:
    from datetime import UTC, datetime

    from netprobe.enumeration.service import ServiceObservation

    scope_path = FIXTURES / "valid_scope.yaml"
    observation = ServiceObservation(
        host="127.0.0.1",
        port=8080,
        protocol="http",
        observed_at=datetime.now(UTC).isoformat(),
        status="observed",
        details={"status_line": "HTTP/1.1 200 OK"},
    )

    def fake_run(awaitable):
        awaitable.close()
        return observation

    monkeypatch.setattr("netprobe.cli.asyncio.run", fake_run)
    result = main(
        [
            "check-http",
            "--scope",
            str(scope_path),
            "--target",
            "127.0.0.1",
            "--port",
            "8080",
            "--i-have-authorization",
            "--artifact-dir",
            str(tmp_path / "assessments"),
        ]
    )
    assert result == EXIT_OK
    output = json.loads(capsys.readouterr().out)
    artifact_path = Path(output["assessment_artifact"])
    stored = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert stored["metadata"]["authorization_confirmed"] is True
    assert stored["observations"][0]["host"] == "127.0.0.1"
    assert len(stored["findings"]) == 1
    assert artifact_path.stat().st_mode & 0o777 == 0o600

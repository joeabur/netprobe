import asyncio
from datetime import UTC, datetime

import pytest

from netprobe.checks.http import HTTP_CHECKS, registered_check_ids, run_checks
from netprobe.enumeration.service import ServiceObservation, _parse_http_head, inspect_service


def http_observation(details: dict[str, str | bool | None]) -> ServiceObservation:
    return ServiceObservation(
        host="127.0.0.1",
        port=8080,
        protocol="http",
        observed_at=datetime.now(UTC).isoformat(),
        status="observed",
        details=details,
    )


def test_plugins_report_missing_headers_as_validation_leads() -> None:
    finding_list = run_checks(
        http_observation({"status_line": "HTTP/1.1 200 OK", "server": "fixture"})
    )
    assert [finding.check_id for finding in finding_list] == [HTTP_CHECKS[0].check_id]
    finding = finding_list[0]
    assert finding.status.value == "requires_validation"
    assert finding.confirmed_misconfiguration is False
    assert finding.priority_score >= 0
    assert finding.cvss_score is None
    assert "Content-Security-Policy" in finding.evidence


def test_cookie_check_never_includes_cookie_value() -> None:
    parsed = _parse_http_head(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: session=SECRET_VALUE; Path=/\r\n\r\n"
    )
    assert parsed.get("cookies_observed") == "true"
    assert "SECRET_VALUE" not in str(parsed)
    findings = run_checks(http_observation(parsed))
    cookie_finding = next(
        item for item in findings if item.check_id.endswith("COOKIE-ATTRIBUTES-001")
    )
    assert "SECRET_VALUE" not in cookie_finding.evidence
    assert "Secure" in cookie_finding.evidence


def test_complete_headers_and_cookie_attributes_produce_no_findings() -> None:
    details = _parse_http_head(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Referrer-Policy: no-referrer\r\n"
        b"Set-Cookie: sample=value; Secure; HttpOnly; SameSite=Lax\r\n\r\n"
    )
    assert run_checks(http_observation(details)) == []


def test_registry_ids_are_unique() -> None:
    ids = registered_check_ids()
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_http_check_engine_against_local_fixture() -> None:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nSet-Cookie: sample=not-recorded; Path=/\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        from netprobe.scope import validate_scope_data

        scope = validate_scope_data(
            {"authorized_targets": ["127.0.0.1"], "authorization_confirmed": True}
        )
        observation = await inspect_service(scope, "127.0.0.1", port, protocol="http")
        results = run_checks(observation)
        assert {finding.check_id for finding in results} == {
            "HTTP-SECURITY-HEADERS-001",
            "HTTP-COOKIE-ATTRIBUTES-001",
        }
        assert "not-recorded" not in str([finding.model_dump() for finding in results])
    finally:
        server.close()
        await server.wait_closed()


def test_check_http_dry_run_does_not_connect(capsys, monkeypatch) -> None:
    from pathlib import Path

    from netprobe.cli import EXIT_OK, main

    async def forbidden_connect(*args, **kwargs):
        pytest.fail("check-http dry-run must not open a socket")

    monkeypatch.setattr(asyncio, "open_connection", forbidden_connect)
    scope_path = Path(__file__).parents[1] / "fixtures" / "valid_scope.yaml"
    result = main(
        [
            "check-http",
            "--scope",
            str(scope_path),
            "--target",
            "127.0.0.1",
            "--dry-run",
        ]
    )
    assert result == EXIT_OK
    assert '"network_activity": false' in capsys.readouterr().out

import asyncio

import pytest

from netprobe.enumeration.service import _parse_http_head, inspect_service
from netprobe.scope import ScopeError, validate_scope_data


def loopback_scope():
    return validate_scope_data(
        {"authorized_targets": ["127.0.0.1"], "authorization_confirmed": True}
    )


def test_http_parser_handles_malformed_and_extracts_safe_headers() -> None:
    assert "parse_error" in _parse_http_head(b"not http")
    parsed = _parse_http_head(
        b"HTTP/1.1 200 OK\r\nServer: local-fixture\r\n"
        b"Location: /?token=do-not-retain\r\nContent-Type: text/plain\r\n\r\n"
    )
    assert parsed["status_line"] == "HTTP/1.1 200 OK"
    assert parsed["server"] == "local-fixture"
    assert parsed["content-type"] == "text/plain"
    assert "location" not in parsed
    assert "do-not-retain" not in str(parsed)


@pytest.mark.asyncio
async def test_service_inspection_rejects_remote_target_before_socket(monkeypatch) -> None:
    async def forbidden_connect(*args, **kwargs):
        pytest.fail("out-of-scope host must never reach socket API")

    monkeypatch.setattr(asyncio, "open_connection", forbidden_connect)
    with pytest.raises(ScopeError):
        await inspect_service(loopback_scope(), "198.51.100.10", 80)


@pytest.mark.asyncio
async def test_http_inspection_against_isolated_local_server() -> None:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: netprobe-test\r\nContent-Type: text/plain\r\n\r\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await inspect_service(loopback_scope(), "127.0.0.1", port, protocol="http")
        assert result.status == "observed"
        assert result.details["status_line"] == "HTTP/1.1 200 OK"
        assert result.details["server"] == "netprobe-test"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_ssh_banner_is_bounded_and_unverified() -> None:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-local-fixture\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await inspect_service(loopback_scope(), "127.0.0.1", port, protocol="ssh")
        assert result.details["banner"] == "SSH-2.0-local-fixture"
        assert "unverified" in result.limitations
    finally:
        server.close()
        await server.wait_closed()


def test_enumerate_cli_dry_run_validates_and_does_not_connect(capsys, monkeypatch) -> None:
    from pathlib import Path

    from netprobe.cli import EXIT_OK, main

    async def forbidden_connect(*args, **kwargs):
        pytest.fail("enumeration dry-run must not open sockets")

    monkeypatch.setattr(asyncio, "open_connection", forbidden_connect)
    scope_path = Path(__file__).parents[1] / "fixtures" / "valid_scope.yaml"
    result = main(
        [
            "enumerate",
            "--scope",
            str(scope_path),
            "--target",
            "127.0.0.1",
            "--port",
            "8080",
            "--dry-run",
        ]
    )
    assert result == EXIT_OK
    assert '"network_activity": false' in capsys.readouterr().out

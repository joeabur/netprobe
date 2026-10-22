import asyncio

import pytest

from netprobe.scanner import tcp
from netprobe.scanner.tcp import PortState, get_ports, parse_ports, scan_tcp
from netprobe.scope import ScopeError, validate_scope_data


def loopback_scope(target: str = "127.0.0.1"):
    return validate_scope_data({"authorized_targets": [target], "authorization_confirmed": True})


@pytest.mark.parametrize(
    ("value", "expected"),
    [("22,80,443", (22, 80, 443)), ("80-82,443", (80, 81, 82, 443))],
)
def test_parse_ports(value: str, expected: tuple[int, ...]) -> None:
    assert parse_ports(value) == expected


@pytest.mark.parametrize("value", ["", "0", "65536", "10-2", "1-100", "80,,443", "ssh"])
def test_parse_ports_rejects_invalid_or_oversized_input(value: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(value)


def test_get_ports_requires_one_selection() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        get_ports()
    with pytest.raises(ValueError, match="exactly one"):
        get_ports(profile="web", ports="80")


@pytest.mark.asyncio
async def test_out_of_scope_target_is_rejected_before_socket(monkeypatch) -> None:
    async def forbidden_connect(*args, **kwargs):
        pytest.fail("socket must not be opened for an unauthorized target")

    monkeypatch.setattr(tcp.asyncio, "open_connection", forbidden_connect)
    with pytest.raises(ScopeError, match="outside the authorized scope"):
        await scan_tcp(loopback_scope(), "192.0.2.10", (80,))


@pytest.mark.asyncio
async def test_concurrency_is_bounded(monkeypatch) -> None:
    active = 0
    maximum = 0

    class Writer:
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def fake_connect(*, host: str, port: int):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.005)
        active -= 1
        return asyncio.StreamReader(), Writer()

    monkeypatch.setattr(tcp.asyncio, "open_connection", fake_connect)
    results = await scan_tcp(loopback_scope(), "127.0.0.1", tuple(range(1000, 1008)), concurrency=2)
    assert len(results) == 8
    assert maximum == 2
    assert all(result.state is PortState.OPEN for result in results)


@pytest.mark.asyncio
async def test_cancellation_propagates(monkeypatch) -> None:
    started = asyncio.Event()

    async def pending_connect(*args, **kwargs):
        started.set()
        await asyncio.Future()

    monkeypatch.setattr(tcp.asyncio, "open_connection", pending_connect)
    task = asyncio.create_task(scan_tcp(loopback_scope(), "127.0.0.1", (80,)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_scan_against_isolated_local_server() -> None:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        results = await scan_tcp(loopback_scope(), "127.0.0.1", (port,))
        assert results[0].port == port
        assert results[0].state is PortState.OPEN
    finally:
        server.close()
        await server.wait_closed()


def test_cli_rejects_out_of_scope_target_without_active_ack(capsys) -> None:
    from pathlib import Path

    from netprobe.cli import EXIT_INPUT_ERROR, main

    scope_path = Path(__file__).parents[1] / "fixtures" / "valid_scope.yaml"
    result = main(["scan", "--scope", str(scope_path), "--target", "198.51.100.2", "--dry-run"])
    assert result == EXIT_INPUT_ERROR
    assert "outside the authorized scope" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("target", "extra_args", "message"),
    [
        ("127.0.0.0/30", [], "one host at a time"),
        ("127.0.0.1", ["--concurrency", "17"], "concurrency must be between"),
        ("127.0.0.1", ["--timeout", "6"], "timeout must be greater than"),
    ],
)
def test_cli_dry_run_applies_active_scan_limits(
    capsys, monkeypatch, target: str, extra_args: list[str], message: str
) -> None:
    from pathlib import Path

    from netprobe.cli import EXIT_INPUT_ERROR, main

    def forbidden_connect(*args, **kwargs):
        pytest.fail("dry-run must never initiate a network connection")

    monkeypatch.setattr(tcp.asyncio, "open_connection", forbidden_connect)
    scope_path = Path(__file__).parents[1] / "fixtures" / "valid_scope.yaml"
    result = main(
        [
            "scan",
            "--scope",
            str(scope_path),
            "--target",
            target,
            "--ports",
            "80",
            "--dry-run",
            *extra_args,
        ]
    )
    assert result == EXIT_INPUT_ERROR
    assert message in capsys.readouterr().err

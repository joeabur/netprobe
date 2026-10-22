import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from netprobe.assessment import run_assessment
from netprobe.checks.tls import check_tls_certificate
from netprobe.enumeration.service import ServiceObservation, _certificate_details
from netprobe.scope import ScopeError, validate_scope_data


def loopback_scope():
    return validate_scope_data(
        {"authorized_targets": ["127.0.0.1"], "authorization_confirmed": True}
    )


def test_certificate_metadata_reports_dates_and_ip_san() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local-fixture")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    details = _certificate_details(der, "127.0.0.1")
    assert details["certificate_target_ip_match"] is True
    assert details["certificate_expired"] is False
    assert details["certificate_not_yet_valid"] is False
    assert "CN=local-fixture" in str(details["certificate_subject"])


def test_tls_check_emits_validation_lead_for_expiry_and_ip_mismatch() -> None:
    observation = ServiceObservation(
        host="127.0.0.1",
        port=443,
        protocol="https",
        observed_at=datetime.now(UTC).isoformat(),
        status="observed",
        details={
            "certificate_present": True,
            "certificate_expired": True,
            "certificate_target_ip_match": False,
            "certificate_not_after": "2020-01-01T00:00:00+00:00",
            "certificate_san": "DNS:fixture.test",
        },
    )
    findings = check_tls_certificate(observation)
    assert {item.check_id for item in findings} == {
        "TLS-CERT-EXPIRED-001",
        "TLS-CERT-IP-SAN-001",
    }
    assert all(item.status.value == "requires_validation" for item in findings)
    assert all(item.cvss_score is None for item in findings)


@pytest.mark.asyncio
async def test_assessment_orchestrates_loopback_http_and_findings() -> None:
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nServer: local-fixture\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await run_assessment(
            loopback_scope(),
            "127.0.0.1",
            (port,),
            protocol_overrides={port: "http"},
        )
        assert result.target == "127.0.0.1"
        assert result.port_results[0].state.value == "open"
        assert result.observations[0].protocol == "http"
        assert any(finding.check_id == "HTTP-SECURITY-HEADERS-001" for finding in result.findings)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_assessment_rejects_non_loopback_before_network() -> None:
    with pytest.raises(ScopeError):
        await run_assessment(loopback_scope(), "192.0.2.1", (80,))

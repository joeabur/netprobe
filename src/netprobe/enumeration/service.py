"""Bounded, non-authenticating service observations for isolated loopback labs."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import ssl
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal, cast

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from netprobe.scanner.tcp import validate_scan_request
from netprobe.scope import ValidatedScope

MAX_RESPONSE_BYTES = 4096
MAX_BANNER_BYTES = 512

Protocol = Literal["auto", "tcp", "http", "https", "ssh", "smtp", "ftp"]


@dataclass(frozen=True)
class ServiceObservation:
    host: str
    port: int
    protocol: str
    observed_at: str
    status: str
    details: dict[str, str | bool | None]
    limitations: str = "Banner and handshake observations are unverified identification clues."

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def infer_protocol(port: int) -> str:
    """Select only well-known safe greeting/handshake parsers; unknown ports stay TCP-only."""
    return {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
    }.get(port, "tcp")


def _clean_text(value: bytes, limit: int) -> str:
    text = value[:limit].decode("utf-8", errors="replace")
    return "".join(char for char in text if char.isprintable() or char in "\r\n\t").strip()


def _parse_http_head(data: bytes) -> dict[str, str | bool | None]:
    if len(data) > MAX_RESPONSE_BYTES:
        data = data[:MAX_RESPONSE_BYTES]
    lines = data.split(b"\r\n")
    if not lines or not re.match(rb"^HTTP/\d(?:\.\d)? [0-9]{3}(?:\s|$)", lines[0]):
        return {"parse_error": "malformed or incomplete HTTP status line"}
    status_line = _clean_text(lines[0], 256)
    fields: dict[str, str | bool | None] = {"status_line": status_line}
    set_cookie_values: list[bytes] = []
    for line in lines[1:]:
        if not line:
            break
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        normalized = name.decode("ascii", errors="ignore").strip().lower()
        if normalized in {
            "server",
            "content-type",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        }:
            fields[normalized] = _clean_text(value, 512)
        elif normalized == "set-cookie":
            # Never retain cookie values; expose only presence and security-attribute flags.
            set_cookie_values.append(value.lower())
    if set_cookie_values:
        cookie_attributes = [
            {part.strip().split(b"=", 1)[0] for part in cookie.split(b";")[1:]}
            for cookie in set_cookie_values
        ]
        fields["cookies_observed"] = "true"
        fields["cookies_missing_secure"] = str(
            any(b"secure" not in attrs for attrs in cookie_attributes)
        ).lower()
        fields["cookies_missing_httponly"] = str(
            any(b"httponly" not in attrs for attrs in cookie_attributes)
        ).lower()
        fields["cookies_missing_samesite"] = str(
            any(b"samesite" not in attrs for attrs in cookie_attributes)
        ).lower()
    return fields


async def _read_greeting(reader: asyncio.StreamReader, timeout: float) -> str:
    data = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=timeout)
    return _clean_text(data, MAX_BANNER_BYTES)


async def _inspect_tcp(
    host: str, port: int, protocol: str, timeout: float
) -> dict[str, str | bool | None]:
    if protocol == "https":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=context,
                server_hostname=None,
                limit=MAX_RESPONSE_BYTES,
            ),
            timeout=timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                return {"error": "TLS session metadata unavailable"}
            certificate = ssl_object.getpeercert(binary_form=True)
            details: dict[str, str | bool | None] = {
                "tls_version": ssl_object.version(),
                "certificate_present": bool(certificate),
                "certificate_sha256": hashlib.sha256(certificate).hexdigest()
                if certificate
                else None,
                "certificate_note": (
                    "Trust-chain validation and cipher inventory are not performed."
                ),
            }
            if certificate:
                details.update(_certificate_details(certificate, host))
            return details
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host=host, port=port, limit=MAX_RESPONSE_BYTES),
        timeout=timeout,
    )
    try:
        if protocol == "http":
            # Keep the request fully constant; no caller-controlled bytes enter the request.
            writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            try:
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
            except asyncio.IncompleteReadError as exc:
                response = exc.partial
            except asyncio.LimitOverrunError:
                return {"parse_error": "HTTP headers exceed the response-size limit"}
            return _parse_http_head(response)
        if protocol in {"ssh", "smtp", "ftp"}:
            if protocol == "ssh":
                # SSH servers send their identification string first; no client auth is attempted.
                greeting = await _read_greeting(reader, timeout)
            else:
                # SMTP and FTP greeting collection sends no commands or credentials.
                greeting = await _read_greeting(reader, timeout)
            return {"banner": greeting or None}
        return {"tcp_connected": True, "application_protocol": "not inspected"}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def _certificate_details(der_certificate: bytes, target_ip: str) -> dict[str, str | bool | None]:
    """Summarize certificate identity and date validity without claiming chain trust."""
    certificate = x509.load_der_x509_certificate(der_certificate)
    now = datetime.now(UTC)
    sans: list[str] = []
    ip_matches = False
    try:
        san_extension = cast(
            x509.SubjectAlternativeName,
            certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value,
        )
    except x509.ExtensionNotFound:
        san_extension = None
    if san_extension is not None:
        for name in san_extension:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                value = str(name.value)
                sans.append(f"IP:{value}")
                ip_matches |= value == target_ip
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    return {
        "certificate_subject": certificate.subject.rfc4514_string(),
        "certificate_issuer": certificate.issuer.rfc4514_string(),
        "certificate_not_before": not_before.isoformat(),
        "certificate_not_after": not_after.isoformat(),
        "certificate_expired": now > not_after,
        "certificate_not_yet_valid": now < not_before,
        "certificate_san": ", ".join(sans)[:1024],
        "certificate_target_ip_match": ip_matches,
    }


async def inspect_service(
    scope: ValidatedScope,
    target: str,
    port: int,
    *,
    protocol: Protocol = "auto",
    timeout: float = 2.0,
) -> ServiceObservation:
    """Inspect one explicitly scoped loopback service without authentication or state changes."""
    host = validate_scan_request(scope, target, (port,), concurrency=1, timeout=timeout)
    if protocol == "auto":
        selected = infer_protocol(port)
    else:
        selected = protocol
    observed_at = datetime.now(UTC).isoformat()
    try:
        details = await _inspect_tcp(host, port, selected, timeout)
    except TimeoutError:
        details = {"error": "connection or response timed out"}
        status = "incomplete"
    except (OSError, ssl.SSLError, ValueError) as exc:
        details = {"error": type(exc).__name__}
        status = "incomplete"
    else:
        status = "observed"

    # Defensive invariant: host must remain literal loopback; no hostnames reach socket APIs.
    if not ipaddress.ip_address(host).is_loopback:
        raise RuntimeError("internal loopback boundary violation")
    return ServiceObservation(host, port, selected, observed_at, status, details)

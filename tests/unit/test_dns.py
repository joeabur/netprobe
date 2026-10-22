import pytest

from netprobe.dns import query_dns, validate_dns_request
from netprobe.scope import ScopeError, validate_scope_data


def scope():
    return validate_scope_data(
        {"authorized_targets": ["127.0.0.1"], "authorization_confirmed": True}
    )


@pytest.mark.parametrize("name", ["localhost", "service.lab.test", "service.lab.test."])
def test_dns_request_allows_reserved_names(name: str) -> None:
    assert validate_dns_request(scope(), "127.0.0.1", name, "A").endswith(".")


@pytest.mark.parametrize("name", ["example.com", "lab.test.example", "", "bad name"])
def test_dns_request_rejects_external_or_malformed_names(name: str) -> None:
    with pytest.raises(ValueError):
        validate_dns_request(scope(), "127.0.0.1", name, "A")


def test_dns_request_rejects_unscoped_resolver_and_types() -> None:
    with pytest.raises(ScopeError):
        validate_dns_request(scope(), "192.0.2.53", "lab.test", "A")
    with pytest.raises(ValueError, match="unsupported record type"):
        validate_dns_request(scope(), "127.0.0.1", "lab.test", "AXFR")


@pytest.mark.asyncio
async def test_query_dns_uses_only_configured_loopback_resolver(monkeypatch) -> None:
    import dns.asyncresolver

    created: dict[str, object] = {}

    class Resolver:
        def __init__(self, *, configure: bool) -> None:
            created["configure"] = configure
            self.nameservers: list[str] = []
            self.port = 0
            self.timeout = 0.0
            self.lifetime = 0.0

        async def resolve(self, name, record_type, **kwargs):
            created["query"] = (name, record_type)

            class Answer:
                rrset = ["127.0.0.2", "127.0.0.3"]

                def __iter__(self):
                    return iter(self.rrset)

            return Answer()

    monkeypatch.setattr(dns.asyncresolver, "Resolver", Resolver)
    result = await query_dns(scope(), "127.0.0.1", "lab.test", "A")
    assert result.status == "answered"
    assert result.answers == ("127.0.0.2", "127.0.0.3")
    assert created["configure"] is False
    assert created["query"] == ("lab.test.", "A")

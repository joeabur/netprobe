import pytest

from netprobe.scope import ScopeError, parse_target, validate_scope_data


@pytest.mark.parametrize("value", ["127.0.0.1", "127.0.0.0/8", "::1", "::1/128", "localhost"])
def test_loopback_targets_are_parsed(value: str) -> None:
    target = parse_target(value)
    assert target.original == value


@pytest.mark.parametrize("value", ["example.test", "192.168.1.10", "0.0.0.0/0", "::/0"])
def test_non_loopback_targets_are_rejected(value: str) -> None:
    with pytest.raises(ScopeError):
        validate_scope_data({"authorized_targets": [value], "authorization_confirmed": True})


@pytest.mark.parametrize("value", ["", " 127.0.0.1", "127.0.0.1/24", "127.0.0.999", "host:80"])
def test_malformed_or_ambiguous_targets_are_rejected(value: str) -> None:
    with pytest.raises(ScopeError):
        parse_target(value)


def test_requires_explicit_acknowledgment() -> None:
    with pytest.raises(ScopeError, match="authorization_confirmed"):
        validate_scope_data({"authorized_targets": ["localhost"]})


def test_exclusion_must_be_inside_scope() -> None:
    with pytest.raises(ScopeError, match="outside authorized scope"):
        validate_scope_data(
            {
                "authorized_targets": ["127.0.0.1"],
                "exclusions": ["127.0.0.2"],
                "authorization_confirmed": True,
            }
        )


def test_permits_respects_scope_and_exclusions() -> None:
    scope = validate_scope_data(
        {
            "authorized_targets": ["127.0.0.0/8"],
            "exclusions": ["127.0.0.2"],
            "authorization_confirmed": True,
        }
    )
    assert scope.permits("127.0.0.1")
    assert not scope.permits("127.0.0.2")
    assert not scope.permits("192.168.1.1")

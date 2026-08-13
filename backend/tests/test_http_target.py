import json
import socket

import httpx
import pytest

from app.config import Settings
from app.core.rules import RULES
from app.core.targets import (
    AuthorizedHttpTarget,
    TargetConfigurationError,
    TargetRequestError,
    validate_target_url,
)


def enabled_settings(**overrides) -> Settings:
    values = {
        "enable_network_targets": True,
        "http_target_allowlist": "rag.example.test",
        "allow_private_targets": False,
        "allow_insecure_http": False,
        "max_response_bytes": 1000,
    }
    values.update(overrides)
    return Settings(**values)


def public_dns(*_args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def test_allowlisted_public_https_target(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", public_dns)
    assert (
        validate_target_url("https://rag.example.test/query", enabled_settings())
        == "https://rag.example.test/query"
    )


@pytest.mark.parametrize(
    ("url", "settings", "message"),
    [
        ("https://other.example.test/query", enabled_settings(), "allowlist"),
        (
            "http://rag.example.test/query",
            enabled_settings(allow_insecure_http=False),
            "Plain HTTP",
        ),
        ("https://user:pass@rag.example.test/query", enabled_settings(), "Credentials"),
    ],
)
def test_unsafe_target_configuration_is_rejected(monkeypatch, url, settings, message):
    monkeypatch.setattr(socket, "getaddrinfo", public_dns)
    with pytest.raises(TargetConfigurationError, match=message):
        validate_target_url(url, settings)


def test_private_dns_result_is_rejected(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(TargetConfigurationError, match="non-public"):
        validate_target_url("https://rag.example.test/query", enabled_settings())


def test_authorized_target_contract(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", public_dns)

    def handler(request: httpx.Request):
        body = json.loads(request.content)
        assert body["security_context"]["control_id"] == "PI-001"
        assert request.headers["authorization"] == "Bearer test-token"
        return httpx.Response(200, json={"data": {"answer": "I cannot reveal policies."}})

    target = AuthorizedHttpTarget(
        "https://rag.example.test/query",
        "data.answer",
        enabled_settings(),
        "test-token",
        transport=httpx.MockTransport(handler),
    )
    answer = target.answer(RULES[0])
    assert answer.text == "I cannot reveal policies."


def test_oversized_response_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", public_dns)
    target = AuthorizedHttpTarget(
        "https://rag.example.test/query",
        "answer",
        enabled_settings(max_response_bytes=10),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"answer": "x" * 20})),
    )
    with pytest.raises(TargetRequestError, match="size limit"):
        target.answer(RULES[0])


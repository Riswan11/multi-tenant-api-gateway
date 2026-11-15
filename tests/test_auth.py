from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.auth import AdminAuthenticator, TenantAuthenticator
from gateway.models import TenantConfig, TenantIdentity
from tests.conftest import ADMIN_TOKEN, TENANT_TOKEN


def test_tenant_auth_accepts_api_key_and_bearer_and_rejects_ambiguous_tokens() -> None:
    tenant = TenantConfig.model_validate({
        "id": "tenant-a",
        "api_key": TENANT_TOKEN,
        "allowed_path_prefixes": ["/api"],
        "scopes": [],
        "requests_per_minute": 1,
    })
    authenticator = TenantAuthenticator((tenant,))

    with TestClient(FastAPI()) as client:
        api_key_request = client.build_request("GET", "/", headers={"x-api-key": TENANT_TOKEN})
        bearer_request = client.build_request(
            "GET",
            "/",
            headers={"authorization": f"Bearer {TENANT_TOKEN}"},
        )
        ambiguous_request = client.build_request(
            "GET",
            "/",
            headers=[
                ("x-api-key", TENANT_TOKEN),
                ("authorization", f"Bearer {TENANT_TOKEN}"),
            ],
        )

        expected_identity = TenantIdentity(
            id="tenant-a",
            allowed_path_prefixes=("/api",),
            scopes=(),
            requests_per_minute=1,
        )
        authenticated_tenant = authenticator.authenticate(api_key_request)
        assert authenticated_tenant == expected_identity
        assert authenticator.authenticate(bearer_request) == expected_identity
        assert authenticator.authenticate(ambiguous_request) is None
        assert authenticator.authenticate(client.build_request("GET", "/")) is None
        assert not hasattr(authenticated_tenant, "api_key")


def test_admin_auth_accepts_only_the_correct_bearer_token() -> None:
    authenticator = AdminAuthenticator(ADMIN_TOKEN)

    with TestClient(FastAPI()) as client:
        correct = client.build_request(
            "GET",
            "/",
            headers={"authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        incorrect = client.build_request(
            "GET",
            "/",
            headers={"authorization": "Bearer wrong-token"},
        )
        wrong_scheme = client.build_request("GET", "/", headers={"x-api-key": ADMIN_TOKEN})

        assert authenticator.authenticate(correct)
        assert not authenticator.authenticate(incorrect)
        assert not authenticator.authenticate(wrong_scheme)

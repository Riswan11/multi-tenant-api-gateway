from __future__ import annotations

import pytest
from pydantic import ValidationError

from gateway.models import GatewayConfig, RouteConfig, RouteRegistry
from tests.conftest import ADMIN_TOKEN, TENANT_TOKEN


def test_gateway_config_validates_and_rejects_duplicate_ids_and_credentials() -> None:
    config = GatewayConfig.model_validate({
        "admin_token": ADMIN_TOKEN,
        "tenants": [{
            "id": "tenant-a",
            "api_key": TENANT_TOKEN,
            "allowed_path_prefixes": ["/api"],
            "requests_per_minute": 10,
        }],
        "routes": [{
            "id": "catalog",
            "prefix": "/api",
            "target": "http://upstream.test",
        }],
    })

    assert config.tenants[0].allowed_path_prefixes == ("/api",)
    assert config.port == 8080

    with pytest.raises(ValidationError, match="tenant IDs must be unique"):
        GatewayConfig.model_validate({
            "admin_token": ADMIN_TOKEN,
            "tenants": [
                {
                    "id": "tenant-a",
                    "api_key": TENANT_TOKEN,
                    "allowed_path_prefixes": ["/api"],
                    "requests_per_minute": 10,
                },
                {
                    "id": "tenant-a",
                    "api_key": "different-token-that-is-long-enough-for-tests",
                    "allowed_path_prefixes": ["/api"],
                    "requests_per_minute": 10,
                },
            ],
        })


def test_route_registry_selects_longest_prefix_and_supports_live_changes() -> None:
    registry = RouteRegistry((
        RouteConfig.model_validate({
            "id": "api",
            "prefix": "/api",
            "target": "http://upstream.test",
        }),
        RouteConfig.model_validate({
            "id": "items",
            "prefix": "/api/items",
            "target": "https://items.test",
        }),
    ))

    assert registry.match("/api/items/1").id == "items"
    assert registry.match("/api/items-extra").id == "api"
    assert registry.match("/unknown") is None
    registry.upsert(RouteConfig.model_validate({
        "id": "items",
        "prefix": "/products",
        "target": "https://products.test",
    }))
    assert registry.match("/products/1").target == "https://products.test"
    assert registry.remove("items")
    assert registry.match("/products/1") is None


@pytest.mark.parametrize(
    "route",
    [
        {"id": "bad", "prefix": "/api/../admin", "target": "http://upstream.test"},
        {"id": "bad", "prefix": "/api", "target": "file:///etc/passwd"},
        {"id": "bad", "prefix": "/api", "target": "http://user:pass@upstream.test"},
    ],
)
def test_route_config_rejects_unsafe_paths_and_targets(route: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        RouteConfig.model_validate(route)

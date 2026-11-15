from __future__ import annotations

import asyncio

from gateway.models import RouteConfig, TenantConfig
from gateway.policy import TenantPolicyEngine


def _tenant(**overrides: object) -> TenantConfig:
    return TenantConfig.model_validate({
        "id": "tenant-a",
        "api_key": "tenant-token-that-is-long-enough-for-tests-123",
        "allowed_path_prefixes": ["/api"],
        "scopes": ["catalog:read"],
        "requests_per_minute": 2,
        **overrides,
    })


def _route(**overrides: object) -> RouteConfig:
    return RouteConfig.model_validate({
        "id": "catalog",
        "prefix": "/api",
        "target": "http://upstream.test",
        "required_scopes": ["catalog:read"],
        **overrides,
    })


def test_policy_enforces_path_prefix_segment_boundaries() -> None:
    policy = TenantPolicyEngine()
    tenant, route = _tenant(), _route()

    assert asyncio.run(policy.evaluate(tenant, "/api/items", route)) == (True, "allowed")
    assert asyncio.run(policy.evaluate(tenant, "/apix/items", route)) == (
        False,
        "path_not_allowed",
    )


def test_policy_checks_scope_before_consuming_quota() -> None:
    policy = TenantPolicyEngine()
    tenant = _tenant(requests_per_minute=1)

    assert asyncio.run(policy.evaluate(
        tenant,
        "/api/items",
        _route(required_scopes=("catalog:write",)),
    )) == (False, "scope_required")
    assert asyncio.run(policy.evaluate(tenant, "/api/items", _route())) == (True, "allowed")


def test_policy_counts_concurrent_requests_atomically() -> None:
    policy = TenantPolicyEngine()
    tenant = _tenant(requests_per_minute=2)
    route = _route()

    async def evaluate_many() -> list[tuple[bool, str]]:
        return await asyncio.gather(*(
            policy.evaluate(tenant, "/api/items", route)
            for _ in range(5)
        ))

    results = asyncio.run(evaluate_many())
    assert sum(allowed for allowed, _ in results) == 2
    assert sum(reason == "rate_limit_exceeded" for _, reason in results) == 3

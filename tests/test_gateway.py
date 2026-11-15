from __future__ import annotations

import httpx

from gateway.main import _filtered_headers
from tests.conftest import ADMIN_TOKEN, TENANT_TOKEN


def test_proxy_strips_connection_nominated_headers() -> None:
    headers = httpx.Headers({
        "connection": "x-private",
        "content-type": "text/plain",
        "x-private": "must-not-reach-upstream",
    })

    forwarded_names = {
        name.lower()
        for name, _ in _filtered_headers(headers, request_headers=True)
    }

    assert b"connection" not in forwarded_names
    assert b"x-private" not in forwarded_names
    assert b"content-type" in forwarded_names


def test_upstream_url_preserves_query_without_adding_empty_delimiter() -> None:
    from gateway.main import _upstream_url
    from gateway.models import RouteConfig

    route = RouteConfig.model_validate({
        "id": "api",
        "prefix": "/api",
        "target": "http://upstream.test/base",
    })

    assert str(_upstream_url(route, "/api/items", b"")) == (
        "http://upstream.test/base/api/items"
    )
    assert str(_upstream_url(route, "/api/items", b"q=one")) == (
        "http://upstream.test/base/api/items?q=one"
    )


def test_proxy_streams_request_and_preserves_upstream_response(make_client) -> None:
    upstream_requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        body = await request.aread()
        return httpx.Response(
            201,
            content=b"upstream:" + body,
            headers=[
                ("content-type", "text/plain"),
                ("set-cookie", "first=1"),
                ("set-cookie", "second=2"),
            ],
        )

    with make_client(handle) as client:
        response = client.post(
            "/api/items?q=one",
            content=b"hello",
            headers={
                "authorization": f"Bearer {TENANT_TOKEN}",
                "connection": "x-private",
            },
        )

    assert response.status_code == 201
    assert response.content == b"upstream:hello"
    assert response.headers.get_list("set-cookie") == ["first=1", "second=2"]
    assert response.headers["x-request-id"]
    assert len(upstream_requests) == 1
    assert str(upstream_requests[0].url) == "http://upstream.test/api/items?q=one"
    assert upstream_requests[0].headers.get("x-api-key") is None
    assert upstream_requests[0].headers.get("authorization") is None


def test_authentication_allowlist_and_scope_failures_never_reach_upstream(
    make_client,
    audit_logger,
) -> None:
    upstream_requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    with make_client(
        handle,
        allowed_path_prefixes=("/api",),
        scopes=(),
        required_scopes=("catalog:read",),
    ) as client:
        unauthenticated = client.get("/api/items")
        disallowed = client.get("/private", headers={"x-api-key": TENANT_TOKEN})
        missing_scope = client.get("/api/items", headers={"x-api-key": TENANT_TOKEN})

    assert unauthenticated.status_code == 401
    assert disallowed.status_code == 403
    assert disallowed.json()["error"] == "path_not_allowed"
    assert missing_scope.status_code == 403
    assert missing_scope.json()["error"] == "scope_required"
    assert upstream_requests == []
    assert [entry["policyDecision"] for entry in audit_logger.entries] == [
        "unauthenticated",
        "path_not_allowed",
        "scope_required",
    ]


def test_rate_limit_rejects_requests_before_proxying(make_client) -> None:
    upstream_requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(200)

    with make_client(handle, requests_per_minute=1) as client:
        first = client.get("/api/first", headers={"x-api-key": TENANT_TOKEN})
        limited = client.get("/api/second", headers={"x-api-key": TENANT_TOKEN})

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["error"] == "rate_limit_exceeded"
    assert len(upstream_requests) == 1


def test_admin_can_upsert_list_and_remove_routes_at_runtime(make_client, audit_logger) -> None:
    upstream_requests: list[httpx.Request] = []

    async def handle(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        return httpx.Response(201, content=b"upstream")

    with make_client(
        handle,
        allowed_path_prefixes=("/api", "/extra"),
        required_scopes=(),
    ) as client:
        denied = client.get("/admin/routes")
        assert denied.status_code == 401

        admin_headers = {"authorization": f"Bearer {ADMIN_TOKEN}"}
        created = client.put(
            "/admin/routes/extra",
            headers=admin_headers,
            json={
                "id": "extra",
                "prefix": "/extra",
                "target": "http://upstream.test",
                "required_scopes": [],
            },
        )
        routes = client.get("/admin/routes", headers=admin_headers)
        proxied = client.get("/extra/now", headers={"x-api-key": TENANT_TOKEN})
        removed = client.delete("/admin/routes/extra", headers=admin_headers)
        missing = client.get("/extra/now", headers={"x-api-key": TENANT_TOKEN})

    assert created.status_code == 200
    assert routes.status_code == 200
    assert [route["id"] for route in routes.json()["routes"]] == ["api", "extra"]
    assert proxied.status_code == 201
    assert removed.status_code == 200
    assert missing.status_code == 404
    assert len(upstream_requests) == 1
    assert audit_logger.entries[0]["policyDecision"] == "admin_unauthenticated"
    assert audit_logger.entries[1]["policyDecision"] == "admin_route_updated"


def test_gateway_rejects_encoded_path_traversal(make_client) -> None:
    with make_client() as client:
        for path in ("/api/%2e%2e/private", "/api/%252e%252e/private"):
            response = client.get(path, headers={"x-api-key": TENANT_TOKEN})
            assert response.status_code == 400
            assert response.json()["error"] == "request path must be normalized"

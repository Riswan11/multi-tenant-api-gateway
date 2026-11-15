from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway.audit import AuditLogger
from gateway.main import create_app
from gateway.models import GatewayConfig

TENANT_TOKEN = "tenant-token-that-is-long-enough-for-integration-123"
ADMIN_TOKEN = "admin-token-that-is-long-enough-for-integration-123"


class CapturingAuditLogger(AuditLogger):
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry.copy())


@pytest.fixture
def audit_logger() -> CapturingAuditLogger:
    return CapturingAuditLogger()


@pytest.fixture
def make_client(audit_logger: CapturingAuditLogger):
    def factory(
        handler: httpx.AsyncHandler | None = None,
        *,
        allowed_path_prefixes: tuple[str, ...] = ("/api",),
        scopes: tuple[str, ...] = ("catalog:read",),
        required_scopes: tuple[str, ...] = ("catalog:read",),
        requests_per_minute: int = 20,
    ) -> TestClient:
        config = GatewayConfig.model_validate({
            "admin_token": ADMIN_TOKEN,
            "tenants": [{
                "id": "tenant-a",
                "api_key": TENANT_TOKEN,
                "allowed_path_prefixes": allowed_path_prefixes,
                "scopes": scopes,
                "requests_per_minute": requests_per_minute,
            }],
            "routes": [{
                "id": "api",
                "prefix": "/api",
                "target": "http://upstream.test",
                "required_scopes": required_scopes,
            }],
        })
        transport = httpx.MockTransport(handler) if handler is not None else None
        return TestClient(create_app(
            config,
            audit_logger=audit_logger,
            upstream_transport=transport,
        ))

    return factory

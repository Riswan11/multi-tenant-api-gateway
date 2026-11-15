from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Sequence

from fastapi import Request

from gateway.models import TenantConfig, TenantIdentity

_BEARER = re.compile(r"^Bearer ([^\s]+)$", re.IGNORECASE)


def _token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _presented_token(request: Request) -> str | None:
    api_keys = _header_values(request, "x-api-key")
    authorizations = _header_values(request, "authorization")
    if len(api_keys) + len(authorizations) != 1:
        return None
    if api_keys:
        return api_keys[0] or None
    match = _BEARER.fullmatch(authorizations[0])
    return match.group(1) if match else None


def _header_values(request: Request, name: str) -> list[str]:
    header_name = name.encode("ascii")
    return [
        value.decode("latin-1")
        for key, value in request.headers.raw
        if key.lower() == header_name
    ]


class TenantAuthenticator:
    def __init__(self, tenants: Sequence[TenantConfig]) -> None:
        self._tenants_by_digest = tuple(
            (
                _token_digest(tenant.api_key),
                TenantIdentity(
                    id=tenant.id,
                    allowed_path_prefixes=tenant.allowed_path_prefixes,
                    scopes=tenant.scopes,
                    requests_per_minute=tenant.requests_per_minute,
                ),
            )
            for tenant in tenants
        )

    def authenticate(self, request: Request) -> TenantIdentity | None:
        presented_token = _presented_token(request)
        if presented_token is None:
            return None
        digest = _token_digest(presented_token)
        authenticated_tenant: TenantIdentity | None = None
        for expected_digest, tenant in self._tenants_by_digest:
            if hmac.compare_digest(digest, expected_digest):
                authenticated_tenant = tenant
        return authenticated_tenant


class AdminAuthenticator:
    def __init__(self, token: str) -> None:
        self._digest = _token_digest(token)

    def authenticate(self, request: Request) -> bool:
        authorizations = _header_values(request, "authorization")
        if len(authorizations) != 1:
            return False
        match = _BEARER.fullmatch(authorizations[0])
        return bool(
            match and hmac.compare_digest(_token_digest(match.group(1)), self._digest)
        )

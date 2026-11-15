from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator, model_validator

_ROUTE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MIN_TOKEN_LENGTH = 32


def normalize_prefix(value: str) -> str:
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "?" in value
        or "#" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
    ):
        raise ValueError("must be a normalized absolute path prefix")
    return value.rstrip("/") or "/"


def validate_target(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "must use http(s) and must not contain credentials, query, or fragment"
        )
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("must contain a valid port") from error
    return value.rstrip("/")


class GatewayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RouteConfig(GatewayModel):
    id: StrictStr
    prefix: StrictStr
    target: StrictStr
    required_scopes: tuple[StrictStr, ...] = ()

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _ROUTE_ID.fullmatch(value):
            raise ValueError("must contain 1-64 letters, digits, dots, underscores, or hyphens")
        return value

    @field_validator("prefix")
    @classmethod
    def validate_route_prefix(cls, value: str) -> str:
        return normalize_prefix(value)

    @field_validator("target")
    @classmethod
    def validate_route_target(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("required_scopes")
    @classmethod
    def validate_required_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not scope.strip() for scope in values):
            raise ValueError("scopes must be non-empty strings")
        return tuple(dict.fromkeys(values))


class TenantConfig(GatewayModel):
    id: StrictStr
    api_key: StrictStr
    allowed_path_prefixes: tuple[StrictStr, ...] = Field(min_length=1)
    scopes: tuple[StrictStr, ...] = ()
    requests_per_minute: StrictInt = Field(gt=0)

    @field_validator("id")
    @classmethod
    def validate_tenant_id(cls, value: str) -> str:
        if not value.strip() or len(value) > 128:
            raise ValueError("must be a non-empty string of at most 128 characters")
        return value

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: str) -> str:
        if len(value) < _MIN_TOKEN_LENGTH:
            raise ValueError(f"must contain at least {_MIN_TOKEN_LENGTH} characters")
        return value

    @field_validator("allowed_path_prefixes")
    @classmethod
    def validate_allowed_prefixes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(normalize_prefix(value) for value in values))

    @field_validator("scopes")
    @classmethod
    def validate_tenant_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not scope.strip() for scope in values):
            raise ValueError("scopes must be non-empty strings")
        return tuple(dict.fromkeys(values))


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    id: str
    allowed_path_prefixes: tuple[str, ...]
    scopes: tuple[str, ...]
    requests_per_minute: int


class GatewayConfig(GatewayModel):
    host: StrictStr = "127.0.0.1"
    port: StrictInt = Field(default=8080, ge=1, le=65535)
    admin_token: StrictStr
    tenants: tuple[TenantConfig, ...] = Field(min_length=1)
    routes: tuple[RouteConfig, ...] = ()

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be a non-empty hostname or IP address")
        return value

    @field_validator("admin_token")
    @classmethod
    def validate_admin_token(cls, value: str) -> str:
        if len(value) < _MIN_TOKEN_LENGTH:
            raise ValueError(f"must contain at least {_MIN_TOKEN_LENGTH} characters")
        return value

    @model_validator(mode="after")
    def validate_unique_credentials_and_ids(self) -> GatewayConfig:
        tenant_ids = [tenant.id for tenant in self.tenants]
        if len(tenant_ids) != len(set(tenant_ids)):
            raise ValueError("tenant IDs must be unique")
        api_keys = [tenant.api_key for tenant in self.tenants]
        if len(api_keys) != len(set(api_keys)):
            raise ValueError("tenant API keys must be unique")
        if self.admin_token in api_keys:
            raise ValueError("admin token must differ from every tenant API key")
        route_ids = [route.id for route in self.routes]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("route IDs must be unique")
        return self


class RouteRegistry:
    """Mutable in-memory route table; updates take effect immediately."""

    def __init__(self, routes: tuple[RouteConfig, ...] = ()) -> None:
        self._routes = {route.id: route for route in routes}

    def list(self) -> list[RouteConfig]:
        return sorted(self._routes.values(), key=lambda route: route.id)

    def upsert(self, route: RouteConfig) -> RouteConfig:
        self._routes[route.id] = route
        return route

    def remove(self, route_id: str) -> bool:
        return self._routes.pop(route_id, None) is not None

    def match(self, path: str) -> RouteConfig | None:
        matches = (
            route
            for route in self._routes.values()
            if prefix_matches(route.prefix, path)
        )
        return max(matches, key=lambda route: len(route.prefix), default=None)


def prefix_matches(prefix: str, path: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(f"{prefix}/")

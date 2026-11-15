from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote

import httpx
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gateway.audit import AuditLogger, configure_logging, new_audit_record
from gateway.auth import AdminAuthenticator, TenantAuthenticator
from gateway.models import GatewayConfig, RouteConfig, RouteRegistry
from gateway.policy import TenantPolicyEngine

logger = logging.getLogger(__name__)
_MAX_ADMIN_BODY_BYTES = 64 * 1024
_ROUTE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOP_BY_HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}
_PROXY_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


class RawHeaders(Protocol):
    @property
    def raw(self) -> list[tuple[bytes, bytes]]: ...


class RequestAuditMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        audit_logger: AuditLogger,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.app = app
        self.audit_logger = audit_logger
        self.clock = clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        audit = new_audit_record(scope.get("path", ""))
        start = self.clock()
        scope.setdefault("state", {})["audit"] = audit
        recorded = False

        def finish_audit() -> None:
            nonlocal recorded
            if recorded:
                return
            recorded = True
            audit["latencyMs"] = max(0, round((self.clock() - start) * 1000))
            self.audit_logger.record(audit)

        async def audited_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers = [
                    (name, value)
                    for name, value in headers
                    if name.lower() != b"x-request-id"
                ]
                headers.append((b"x-request-id", audit["requestId"].encode("ascii")))
                message["headers"] = headers
            await send(message)
            if (
                message["type"] == "http.response.body"
                and not message.get("more_body", False)
            ):
                finish_audit()

        try:
            await self.app(scope, receive, audited_send)
        except Exception:
            if audit["policyDecision"] == "not_evaluated":
                audit["policyDecision"] = "internal_error"
            raise
        finally:
            finish_audit()


def _decode_request_path(request: Request) -> str:
    raw_path = request.scope.get("raw_path", request.url.path.encode("utf-8"))
    if re.search(rb"%(?![0-9a-f]{2})", raw_path, re.IGNORECASE):
        raise ValueError("request path contains invalid encoding")
    if re.search(rb"%2f|%5c", raw_path, re.IGNORECASE):
        raise ValueError("encoded path separators are not allowed")
    try:
        path = unquote(raw_path.decode("utf-8"), encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as error:
        raise ValueError("request path contains invalid encoding") from error
    candidate = path
    for _ in range(2):
        if re.search(r"%2f|%5c", candidate, re.IGNORECASE):
            raise ValueError("encoded path separators are not allowed")
        if (
            not candidate.startswith("/")
            or candidate.startswith("//")
            or "\\" in candidate
            or any(segment in {".", ".."} for segment in candidate.split("/"))
            or "\x00" in candidate
        ):
            raise ValueError("request path must be normalized")
        try:
            decoded = unquote(candidate, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("request path contains invalid encoding") from error
        if decoded == candidate:
            break
        candidate = decoded
    return path


def _filtered_headers(
    headers: RawHeaders,
    *,
    request_headers: bool = False,
) -> list[tuple[bytes, bytes]]:
    connection_tokens = {
        token.strip().lower().encode("ascii")
        for name, value in headers.raw
        if name.lower() == b"connection"
        for token in value.decode("latin-1").split(",")
        if token.strip()
    }
    excluded = _HOP_BY_HOP_HEADERS | connection_tokens
    if request_headers:
        excluded |= {
            b"host",
            b"authorization",
            b"x-api-key",
            b"content-length",
        }
    return [
        (name, value)
        for name, value in headers.raw
        if name.lower() not in excluded
    ]


def _upstream_url(route: RouteConfig, path: str, query: bytes) -> httpx.URL:
    base = httpx.URL(route.target)
    base_path = base.path.rstrip("/")
    return base.copy_with(
        path=f"{base_path}{path}" or "/",
        query=query or None,
    )


async def _read_json_body(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise ValueError("invalid content-length header") from error
        if declared_length > _MAX_ADMIN_BODY_BYTES:
            raise ValueError("request body exceeds 64 KiB")

    chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > _MAX_ADMIN_BODY_BYTES:
            raise ValueError("request body exceeds 64 KiB")
        chunks.append(chunk)

    try:
        payload = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid route JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    return payload


def create_app(
    config: GatewayConfig,
    *,
    audit_logger: AuditLogger | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    routes = RouteRegistry(config.routes)
    authenticator = TenantAuthenticator(config.tenants)
    admin_authenticator = AdminAuthenticator(config.admin_token)
    policy_engine = TenantPolicyEngine()
    audit = audit_logger or AuditLogger()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            follow_redirects=False,
            trust_env=False,
            transport=upstream_transport,
        ) as client:
            app.state.upstream_client = client
            yield

    app = FastAPI(
        title="Multi-tenant API Gateway",
        version="1.0.0",
        redirect_slashes=False,
        lifespan=lifespan,
    )
    app.add_middleware(RequestAuditMiddleware, audit_logger=audit)

    def require_admin(request: Request) -> bool:
        if not admin_authenticator.authenticate(request):
            request.state.audit["policyDecision"] = "admin_unauthenticated"
            return False
        request.state.audit["tenantId"] = "admin"
        return True

    @app.get("/admin/routes")
    async def list_routes(request: Request) -> Response:
        if not require_admin(request):
            return JSONResponse(
                {"error": "valid admin bearer token required"},
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        request.state.audit["policyDecision"] = "admin_allowed"
        return JSONResponse({"routes": [route.model_dump(mode="json") for route in routes.list()]})

    @app.put("/admin/routes/{route_id}")
    async def upsert_route(route_id: str, request: Request) -> Response:
        if not require_admin(request):
            return JSONResponse(
                {"error": "valid admin bearer token required"},
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        if not _ROUTE_ID_PATTERN.fullmatch(route_id):
            request.state.audit["policyDecision"] = "admin_invalid_route"
            return JSONResponse({"error": "invalid route id"}, status_code=400)
        try:
            payload = await _read_json_body(request)
            if payload.get("id") != route_id:
                raise ValueError("route id in body must match the URL")
            route = RouteConfig.model_validate(payload)
        except (ValueError, ValidationError) as error:
            request.state.audit["policyDecision"] = "admin_invalid_route"
            if isinstance(error, ValidationError):
                details = error.errors(include_input=False)
                return JSONResponse(
                    {
                        "error": "invalid route configuration",
                        "details": jsonable_encoder(details),
                    },
                    status_code=422,
                )
            status_code = 413 if "exceeds" in str(error) else 400
            return JSONResponse({"error": str(error)}, status_code=status_code)

        routes.upsert(route)
        request.state.audit["policyDecision"] = "admin_route_updated"
        return JSONResponse({"route": route.model_dump(mode="json")})

    @app.delete("/admin/routes/{route_id}")
    async def delete_route(route_id: str, request: Request) -> Response:
        if not require_admin(request):
            return JSONResponse(
                {"error": "valid admin bearer token required"},
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        if not _ROUTE_ID_PATTERN.fullmatch(route_id) or not routes.remove(route_id):
            request.state.audit["policyDecision"] = "admin_route_not_found"
            return JSONResponse({"error": "route not found"}, status_code=404)
        request.state.audit["policyDecision"] = "admin_route_removed"
        return JSONResponse({"deleted": route_id})

    @app.api_route("/", methods=_PROXY_METHODS)
    @app.api_route("/{path:path}", methods=_PROXY_METHODS)
    async def proxy(request: Request, path: str = "") -> Response:
        try:
            request_path = _decode_request_path(request)
        except ValueError as error:
            request.state.audit["policyDecision"] = "invalid_request"
            return JSONResponse({"error": str(error)}, status_code=400)

        request.state.audit["path"] = request_path
        tenant = authenticator.authenticate(request)
        if tenant is None:
            request.state.audit["policyDecision"] = "unauthenticated"
            return JSONResponse(
                {"error": "valid tenant API token required"},
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        request.state.audit["tenantId"] = tenant.id

        if not policy_engine.allows_path(tenant, request_path):
            request.state.audit["policyDecision"] = "path_not_allowed"
            return JSONResponse({"error": "path_not_allowed"}, status_code=403)

        route = routes.match(request_path)
        if route is None:
            request.state.audit["policyDecision"] = "route_not_found"
            return JSONResponse({"error": "no route is configured for this path"}, status_code=404)
        request.state.audit["upstreamTarget"] = route.target

        allowed, reason = await policy_engine.evaluate(tenant, request_path, route)
        if not allowed:
            request.state.audit["policyDecision"] = reason
            headers = {"retry-after": "60"} if reason == "rate_limit_exceeded" else {}
            status_code = 429 if reason == "rate_limit_exceeded" else 403
            return JSONResponse({"error": reason}, status_code=status_code, headers=headers)

        request.state.audit["policyDecision"] = "allowed"
        client: httpx.AsyncClient = request.app.state.upstream_client
        outgoing = client.build_request(
            request.method,
            _upstream_url(
                route,
                request_path,
                request.scope.get("query_string", b""),
            ),
            headers=_filtered_headers(request.headers, request_headers=True),
            content=request.stream(),
        )
        try:
            upstream = await client.send(outgoing, stream=True)
        except httpx.RequestError:
            request.state.audit["policyDecision"] = "upstream_error"
            return JSONResponse(
                {"error": "upstream service unavailable"},
                status_code=502,
            )

        request.state.audit["upstreamResponseCode"] = upstream.status_code

        async def upstream_body() -> AsyncIterator[bytes]:
            try:
                if upstream.is_stream_consumed:
                    if upstream.content:
                        yield upstream.content
                    return
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()

        response = StreamingResponse(
            upstream_body(),
            status_code=upstream.status_code,
        )
        response.raw_headers = _filtered_headers(upstream.headers)
        return response

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, error: Exception) -> JSONResponse:
        logger.exception("unhandled gateway exception", exc_info=error)
        request.state.audit["policyDecision"] = "internal_error"
        return JSONResponse({"error": "internal gateway error"}, status_code=500)

    return app


def load_config(path: str | Path | None = None) -> GatewayConfig:
    config_path = path or os.environ.get("GATEWAY_CONFIG")
    if config_path is None:
        config_json = os.environ.get("GATEWAY_CONFIG_JSON")
        if config_json is None:
            config_path = Path("config.json")
        else:
            try:
                payload = json.loads(config_json)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"unable to load gateway configuration from GATEWAY_CONFIG_JSON: {error}"
                ) from error

    if config_path is not None:
        config_path = Path(config_path)
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"unable to load gateway configuration {config_path}: {error}"
            ) from error
    try:
        return GatewayConfig.model_validate(payload)
    except ValidationError as error:
        details = error.errors(include_input=False)
        raise RuntimeError(f"invalid gateway configuration: {details}") from error


def main() -> None:
    import uvicorn

    try:
        config = load_config()
    except RuntimeError as error:
        raise SystemExit(str(error)) from error
    configure_logging()
    app = create_app(config)
    host, port = config.host, config.port
    del config
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()

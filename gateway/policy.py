from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from gateway.models import RouteConfig, TenantIdentity, prefix_matches

_WINDOW_SECONDS = 60


class TenantPolicyEngine:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._windows: dict[str, tuple[int, int]] = {}
        self._lock = asyncio.Lock()

    def allows_path(self, tenant: TenantIdentity, path: str) -> bool:
        return any(prefix_matches(prefix, path) for prefix in tenant.allowed_path_prefixes)

    async def evaluate(
        self,
        tenant: TenantIdentity,
        path: str,
        route: RouteConfig,
    ) -> tuple[bool, str]:
        if not self.allows_path(tenant, path):
            return False, "path_not_allowed"

        if any(scope not in tenant.scopes for scope in route.required_scopes):
            return False, "scope_required"

        current_window = int(self._clock() // _WINDOW_SECONDS)
        async with self._lock:
            window_id, request_count = self._windows.get(tenant.id, (current_window, 0))
            if window_id != current_window:
                window_id, request_count = current_window, 0
            if request_count >= tenant.requests_per_minute:
                self._windows[tenant.id] = (window_id, request_count)
                return False, "rate_limit_exceeded"
            self._windows[tenant.id] = (window_id, request_count + 1)
        return True, "allowed"

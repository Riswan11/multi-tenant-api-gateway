from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

logger = logging.getLogger("gateway.audit")


class AuditLogger:
    def record(self, entry: dict[str, Any]) -> None:
        logger.info(json.dumps(entry, separators=(",", ":"), ensure_ascii=True))


def new_audit_record(path: str) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "requestId": str(uuid4()),
        "tenantId": None,
        "path": path.split("?", 1)[0],
        "upstreamTarget": None,
        "policyDecision": "not_evaluated",
        "upstreamResponseCode": None,
        "latencyMs": 0,
    }


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

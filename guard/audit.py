"""Privacy-safe audit records for guard decisions.

Audit logs deliberately contain a content digest rather than external content so
they can support incident review without copying potentially sensitive pages
or prompt-injection payloads into another storage location.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .policy import GuardResult


def content_digest(text: str) -> str:
    """Return a stable SHA-256 digest for correlating content without logging it."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_source(source: str) -> str:
    """Remove URL credentials, queries, and fragments before source logging."""

    parts = urlsplit(source)
    if not parts.scheme or not parts.netloc:
        return source
    hostname = parts.hostname or ""
    host = hostname if parts.port is None else f"{hostname}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def event_from_result(result: GuardResult, *, classifier: str, content: str) -> dict[str, Any]:
    """Build a JSON-serializable record with decision metadata only."""

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": "guard_decision",
        "classifier": classifier,
        "decision": result.decision.value,
        "score": round(result.score, 4),
        "provenance": result.provenance.value,
        "source": safe_source(result.source),
        "content_sha256": content_digest(content),
        "content_chars": len(content),
        "reason": result.reason,
    }


def append_event(path: Path, event: dict[str, Any]) -> None:
    """Append one newline-delimited JSON event, creating parent folders as needed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
        handle.write("\n")

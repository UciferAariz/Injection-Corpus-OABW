"""Tests for Day 5 privacy-safe audit logging."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from guard.audit import append_event, event_from_result, safe_source
from guard.policy import evaluate_content
from guard.provenance import tag_untrusted


class AuditTests(unittest.TestCase):
    def test_safe_source_removes_url_secrets(self) -> None:
        source = "https://user:password@example.com/page?token=secret#fragment"
        self.assertEqual(safe_source(source), "https://example.com/page")

    def test_event_never_contains_raw_content(self) -> None:
        content = "unique embedded content that must not reach the audit log"
        result = evaluate_content(tag_untrusted(content, source="https://example.com/?token=abc"), classifier=lambda _: 0.0)

        event = event_from_result(result, classifier="test", content=content)

        self.assertNotIn(content, json.dumps(event))
        self.assertEqual(event["source"], "https://example.com/")
        self.assertEqual(len(event["content_sha256"]), 64)

    def test_append_event_writes_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "audit.jsonl"
            append_event(log_path, {"event": "guard_decision", "score": 0.7})
            self.assertEqual(json.loads(log_path.read_text(encoding="utf-8")), {"event": "guard_decision", "score": 0.7})


if __name__ == "__main__":
    unittest.main()

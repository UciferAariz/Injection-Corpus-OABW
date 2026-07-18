"""End-to-end demo agent for guarded webpage fetching."""

from __future__ import annotations

import argparse
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen

from guard.audit import append_event, event_from_result
from guard.heuristics import heuristic_score
from guard.policy import GuardDecision, evaluate_content
from guard.provenance import tag_untrusted


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self.parts.append(stripped)

    def text(self) -> str:
        return "\n".join(self.parts)


def fetch_source(url: str | None, file_path: Path | None) -> tuple[str, str]:
    if file_path:
        return file_path.read_text(encoding="utf-8"), str(file_path)
    if not url:
        raise ValueError("Provide --url or --file")
    request = Request(url, headers={"User-Agent": "InjectionCorpusDemo/1.0"})
    with urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace"), url


def html_to_text(raw: str) -> str:
    parser = TextExtractor()
    parser.feed(raw)
    text = parser.text()
    return text if text else re.sub(r"<[^>]+>", " ", raw)


def naive_agent_action(page_text: str) -> str:
    lowered = page_text.lower()
    if "ignore previous instructions" in lowered or "send" in lowered and "token" in lowered:
        return "HIJACKED: the unguarded agent would follow the embedded instruction."
    summary = " ".join(page_text.split())[:300]
    return f"SAFE SUMMARY: {summary}"


def guarded_agent_action(page_text: str, source: str, classifier_name: str, audit_log: Path | None = None) -> str:
    if classifier_name == "heuristic":
        result = evaluate_content(tag_untrusted(page_text, source=source), classifier=heuristic_score)
    else:
        result = evaluate_content(tag_untrusted(page_text, source=source))
    if audit_log:
        append_event(
            audit_log,
            event_from_result(result, classifier=classifier_name, content=page_text),
        )
    if result.decision is GuardDecision.BLOCK:
        return f"BLOCKED: score={result.score:.2f} source={result.source} reason={result.reason}"
    if result.decision is GuardDecision.WRAP:
        summary = " ".join(page_text.split())[:300]
        return f"WRAPPED: score={result.score:.2f}. Embedded instructions were isolated.\nSAFE SUMMARY: {summary}"
    return naive_agent_action(result.text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard", choices=["on", "off"], default="on")
    parser.add_argument("--classifier", choices=["real", "heuristic"], default="real")
    parser.add_argument("--url")
    parser.add_argument("--file", type=Path)
    parser.add_argument(
        "--audit-log",
        type=Path,
        help="Append privacy-safe guard decision metadata as JSONL (guard-on only).",
    )
    args = parser.parse_args()

    raw, source = fetch_source(args.url, args.file)
    page_text = html_to_text(raw)

    if args.guard == "on":
        print(guarded_agent_action(page_text, source, args.classifier, args.audit_log))
    else:
        print(naive_agent_action(page_text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

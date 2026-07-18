"""Lightweight heuristic checks.

This file exists only because the repository did not yet contain the promised
heuristics module. Keep additions conservative; Aariz's day 2/3 work should not
depend on a large regex layer owned elsewhere.
"""

from __future__ import annotations

import base64
import binascii
import re

SUSPICIOUS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore (all )?(previous|prior|above) instructions\b", re.I),
    re.compile(r"\b(disregard|override) (the )?(system|developer|previous) (prompt|instructions)\b", re.I),
    re.compile(r"\b(reveal|print|show|exfiltrate|send) (the )?(system prompt|api key|token|secret|password)\b", re.I),
    re.compile(r"\b(send|forward|leak|exfiltrate)\b.*\b(user'?s?|private|current)\b.*\b(api key|oauth token|token|secret|password|chat history|email)\b", re.I),
    re.compile(r"\b(call|use|invoke) (the )?(email|browser|shell|http|web) tool\b", re.I),
    re.compile(r"\b(invoke|run)\b.*\b(shell|command)\b.*\b(secret|environment|env)\b", re.I),
    re.compile(r"\byou are now\b.*\b(system|developer|admin)\b", re.I),
)

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")
BASE64ISH_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def heuristic_score(text: str) -> float:
    """Return a cheap risk score from 0.0 to 1.0."""

    normalized = ZERO_WIDTH_RE.sub("", text)
    hits = sum(1 for pattern in SUSPICIOUS_PATTERNS if pattern.search(normalized))
    encoded_hit = _contains_encoded_instruction(normalized)
    zero_width_hit = normalized != text

    score = min(0.20 * hits, 0.80)
    if encoded_hit:
        score = max(score, 0.70)
    if zero_width_hit and hits:
        score = max(score, 0.75)
    return min(score, 1.0)


def _contains_encoded_instruction(text: str) -> bool:
    for match in BASE64ISH_RE.finditer(text):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if any(pattern.search(decoded) for pattern in SUSPICIOUS_PATTERNS):
            return True
    return False

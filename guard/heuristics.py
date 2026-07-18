"""Lightweight heuristic checks.

This file exists only because the repository did not yet contain the promised
heuristics module. Keep additions conservative; Aariz's day 2/3 work should not
depend on a large regex layer owned elsewhere.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class WeightedPattern:
    pattern: re.Pattern[str]
    weight: float


SUSPICIOUS_PATTERNS: tuple[WeightedPattern, ...] = (
    WeightedPattern(re.compile(r"\bignore (all )?(previous|prior|above) instructions\b", re.I), 0.45),
    WeightedPattern(re.compile(r"\b(disregard|override) (the )?(system|developer|previous|safety) (prompt|policy|instructions)\b", re.I), 0.45),
    WeightedPattern(re.compile(r"\b(reveal|print|show|exfiltrate|send|forward) (the |all |current )?([\w' -]+ )?(system prompt|api key|oauth token|token|secret|password|private messages|chat history|environment secrets)\b", re.I), 0.55),
    WeightedPattern(re.compile(r"\b(answer|respond) only with\b.*\b(account email|oauth token|token|secret|password)\b", re.I), 0.55),
    WeightedPattern(re.compile(r"\b(call|use|invoke) (the )?(email|browser|shell|http|web) tool\b", re.I), 0.45),
    WeightedPattern(re.compile(r"\byou are now\b.*\b(system|developer|admin)\b", re.I), 0.45),
    WeightedPattern(re.compile(r"\btreat (this|the) .{0,40} as (a )?(developer|system) (message|prompt|instruction)\b", re.I), 0.45),
    WeightedPattern(re.compile(r"\b(if blocked|if you are blocked|if this is blocked)\b.*\b(continue|approved|bypass)\b", re.I), 0.35),
    WeightedPattern(re.compile(r"\bdo not (mention|reveal|disclose) (these|this|the) instructions\b", re.I), 0.30),
)

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")
BASE64ISH_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def heuristic_score(text: str) -> float:
    """Return a cheap risk score from 0.0 to 1.0."""

    normalized = ZERO_WIDTH_RE.sub("", text)
    score = sum(weighted.weight for weighted in SUSPICIOUS_PATTERNS if weighted.pattern.search(normalized))
    encoded_hit = _contains_encoded_instruction(normalized)
    zero_width_hit = normalized != text

    if encoded_hit:
        score = max(score, 0.85)
    if zero_width_hit and score:
        score = max(score, 0.85)
    return min(score, 1.0)


def _contains_encoded_instruction(text: str) -> bool:
    for match in BASE64ISH_RE.finditer(text):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if any(weighted.pattern.search(decoded) for weighted in SUSPICIOUS_PATTERNS):
            return True
    return False

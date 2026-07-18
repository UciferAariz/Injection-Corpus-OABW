"""Trusted/untrusted content tagging for indirect prompt-injection defense."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Provenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class TaggedContent:
    text: str
    provenance: Provenance
    source: str = "unknown"


def tag_trusted(text: str, source: str = "user") -> TaggedContent:
    """Mark text supplied directly by the user."""

    return TaggedContent(text=text, provenance=Provenance.TRUSTED, source=source)


def tag_untrusted(text: str, source: str = "external") -> TaggedContent:
    """Mark text fetched from webpages, files, tools, or other external sources."""

    return TaggedContent(text=text, provenance=Provenance.UNTRUSTED, source=source)

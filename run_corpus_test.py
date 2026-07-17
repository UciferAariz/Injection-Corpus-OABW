"""Evaluate guard thresholds against a local corpus.

Expected corpus formats:
- JSONL files under corpus/ with {"text": "...", "label": "malicious|clean"}
- TXT files under corpus/malicious/ and corpus/clean/

Lavya can add or change corpus files independently; this runner only consumes
whatever corpus exists.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from guard.policy import GuardDecision, evaluate_content
from guard.provenance import tag_untrusted


@dataclass(frozen=True)
class Sample:
    text: str
    malicious: bool
    path: Path


def load_samples(root: Path) -> list[Sample]:
    samples: list[Sample] = []
    if not root.exists():
        return samples

    for path in sorted(root.rglob("*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                item = json.loads(line)
                label = str(item.get("label", "")).lower()
                samples.append(
                    Sample(
                        text=str(item["text"]),
                        malicious=label in {"malicious", "attack", "unsafe", "1", "true"},
                        path=Path(f"{path}:{line_number}"),
                    )
                )

    for label_dir, malicious in (("malicious", True), ("clean", False)):
        sample_dir = root / label_dir
        if not sample_dir.exists():
            continue
        for path in sorted(sample_dir.rglob("*.txt")):
            samples.append(Sample(text=path.read_text(encoding="utf-8"), malicious=malicious, path=path))

    return samples


def run(samples: list[Sample]) -> int:
    if not samples:
        print("No corpus samples found. Add JSONL files under corpus/ or TXT files under corpus/malicious and corpus/clean.")
        return 2

    false_positive = 0
    false_negative = 0
    correct = 0

    for sample in samples:
        result = evaluate_content(tag_untrusted(sample.text, source=str(sample.path)))
        predicted_malicious = result.decision is GuardDecision.BLOCK
        if predicted_malicious == sample.malicious:
            correct += 1
        elif predicted_malicious:
            false_positive += 1
            print(f"FALSE POSITIVE {sample.path} score={result.score:.2f} decision={result.decision.value}")
        else:
            false_negative += 1
            print(f"FALSE NEGATIVE {sample.path} score={result.score:.2f} decision={result.decision.value}")

    total = len(samples)
    clean_total = sum(1 for sample in samples if not sample.malicious)
    malicious_total = sum(1 for sample in samples if sample.malicious)
    accuracy = correct / total if total else 0.0
    fpr = false_positive / clean_total if clean_total else 0.0
    fnr = false_negative / malicious_total if malicious_total else 0.0

    print(f"samples={total}")
    print(f"accuracy={accuracy:.3f}")
    print(f"false_positive_rate={fpr:.3f}")
    print(f"false_negative_rate={fnr:.3f}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="corpus", type=Path)
    args = parser.parse_args()
    return run(load_samples(args.corpus))


if __name__ == "__main__":
    raise SystemExit(main())

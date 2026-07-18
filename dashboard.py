"""Generate a static HTML dashboard for corpus evaluation results."""

from __future__ import annotations

import argparse
import html
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from guard.policy import GuardDecision, GuardResult, evaluate_content
from guard.provenance import tag_untrusted
from run_corpus_test import Sample, choose_classifier, load_samples


@dataclass(frozen=True)
class EvaluatedSample:
    sample: Sample
    result: GuardResult
    predicted_malicious: bool


@dataclass(frozen=True)
class DashboardStats:
    total: int
    malicious_total: int
    clean_total: int
    correct: int
    false_positive: int
    false_negative: int
    blocked: int
    wrapped: int
    passed: int

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positive / self.clean_total if self.clean_total else 0.0

    @property
    def false_negative_rate(self) -> float:
        return self.false_negative / self.malicious_total if self.malicious_total else 0.0


def evaluate_samples(samples: list[Sample], classifier_name: str) -> list[EvaluatedSample]:
    classifier = choose_classifier(classifier_name)
    evaluated: list[EvaluatedSample] = []
    for sample in samples:
        result = evaluate_content(
            tag_untrusted(sample.text, source=str(sample.path)),
            classifier=classifier,
        )
        predicted_malicious = result.decision is GuardDecision.BLOCK
        evaluated.append(EvaluatedSample(sample, result, predicted_malicious))
    return evaluated


def summarize(evaluated: list[EvaluatedSample]) -> DashboardStats:
    false_positive = 0
    false_negative = 0
    correct = 0
    blocked = 0
    wrapped = 0
    passed = 0

    for item in evaluated:
        if item.predicted_malicious == item.sample.malicious:
            correct += 1
        elif item.predicted_malicious:
            false_positive += 1
        else:
            false_negative += 1

        if item.result.decision is GuardDecision.BLOCK:
            blocked += 1
        elif item.result.decision is GuardDecision.WRAP:
            wrapped += 1
        else:
            passed += 1

    return DashboardStats(
        total=len(evaluated),
        malicious_total=sum(1 for item in evaluated if item.sample.malicious),
        clean_total=sum(1 for item in evaluated if not item.sample.malicious),
        correct=correct,
        false_positive=false_positive,
        false_negative=false_negative,
        blocked=blocked,
        wrapped=wrapped,
        passed=passed,
    )


def render_dashboard(evaluated: list[EvaluatedSample], stats: DashboardStats, classifier_name: str) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = "\n".join(render_row(item) for item in evaluated)
    sample_note = "No samples found." if not evaluated else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Injection Corpus Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f6f4;
      --panel: #ffffff;
      --ink: #202426;
      --muted: #5d666b;
      --line: #d8dedb;
      --blue: #006f8f;
      --green: #187647;
      --amber: #9a6200;
      --red: #b7332c;
      --shadow: 0 12px 30px rgba(30, 36, 38, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: #fbfcfb;
    }}
    .wrap {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      padding: 28px 0 22px;
      align-items: flex-end;
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: clamp(28px, 4vw, 44px);
      line-height: 1.05;
      letter-spacing: 0;
    }}
    .meta, .subtle {{
      color: var(--muted);
      font-size: 14px;
      line-height: 1.45;
    }}
    main {{ padding: 28px 0 40px; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }}
    .metric, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .metric {{ padding: 18px; min-height: 118px; }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    .metric strong {{
      display: block;
      margin-top: 10px;
      font-size: 34px;
      line-height: 1;
    }}
    .metric b {{
      display: block;
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 400;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 340px minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }}
    .panel {{ padding: 18px; }}
    h2 {{
      margin: 0 0 14px;
      font-size: 18px;
      line-height: 1.2;
    }}
    .bars {{
      display: grid;
      gap: 12px;
    }}
    .bar-label {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 6px;
    }}
    .track {{
      width: 100%;
      height: 10px;
      overflow: hidden;
      border-radius: 999px;
      background: #e7ece9;
    }}
    .fill {{
      height: 100%;
      border-radius: inherit;
      background: var(--blue);
    }}
    .fill.green {{ background: var(--green); }}
    .fill.amber {{ background: var(--amber); }}
    .fill.red {{ background: var(--red); }}
    .tools {{
      display: grid;
      grid-template-columns: minmax(180px, 1fr) 160px 160px;
      gap: 10px;
      margin-bottom: 14px;
    }}
    input, select {{
      width: 100%;
      min-height: 40px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #ffffff;
      color: var(--ink);
      font: inherit;
      padding: 8px 10px;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    table {{
      width: 100%;
      min-width: 840px;
      border-collapse: collapse;
      background: #ffffff;
    }}
    th, td {{
      padding: 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #f9faf9;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    .text-cell {{
      max-width: 380px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 9px;
      color: #ffffff;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      white-space: nowrap;
    }}
    .pill.clean {{ background: var(--green); }}
    .pill.malicious, .pill.block {{ background: var(--red); }}
    .pill.wrap {{ background: var(--amber); }}
    .pill.pass {{ background: var(--green); }}
    .score {{
      width: 88px;
      display: grid;
      gap: 5px;
      color: var(--muted);
      font-size: 13px;
    }}
    .empty {{
      margin: 14px 0 0;
      color: var(--muted);
    }}
    @media (max-width: 860px) {{
      .topbar, .grid {{ display: block; }}
      .topbar .meta {{ margin-top: 12px; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .panel {{ margin-top: 18px; }}
      .tools {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 520px) {{
      .wrap {{ width: min(100% - 20px, 1180px); }}
      .metrics {{ grid-template-columns: 1fr; }}
      .metric strong {{ font-size: 30px; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>Injection Corpus Dashboard</h1>
        <div class="subtle">Corpus guard evaluation for untrusted external content.</div>
      </div>
      <div class="meta">
        Classifier: {escape(classifier_name)}<br>
        Generated: {escape(generated_at)}
      </div>
    </div>
  </header>
  <main class="wrap">
    <section class="metrics" aria-label="Summary metrics">
      {metric("Accuracy", pct(stats.accuracy), f"{stats.correct} of {stats.total} correct")}
      {metric("False positives", pct(stats.false_positive_rate), f"{stats.false_positive} of {stats.clean_total} clean")}
      {metric("False negatives", pct(stats.false_negative_rate), f"{stats.false_negative} of {stats.malicious_total} malicious")}
      {metric("Samples", str(stats.total), f"{stats.malicious_total} malicious / {stats.clean_total} clean")}
    </section>

    <section class="grid">
      <aside class="panel">
        <h2>Decision Mix</h2>
        <div class="bars">
          {bar("Blocked", stats.blocked, stats.total, "red")}
          {bar("Wrapped", stats.wrapped, stats.total, "amber")}
          {bar("Passed", stats.passed, stats.total, "green")}
        </div>
      </aside>

      <section class="panel">
        <h2>Samples</h2>
        <div class="tools">
          <input id="search" type="search" placeholder="Search corpus text or path" aria-label="Search corpus text or path">
          <select id="labelFilter" aria-label="Filter by label">
            <option value="all">All labels</option>
            <option value="malicious">Malicious</option>
            <option value="clean">Clean</option>
          </select>
          <select id="decisionFilter" aria-label="Filter by decision">
            <option value="all">All decisions</option>
            <option value="block">Block</option>
            <option value="wrap">Wrap</option>
            <option value="pass">Pass</option>
          </select>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Decision</th>
                <th>Score</th>
                <th>Path</th>
                <th>Text</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody id="rows">
              {rows}
            </tbody>
          </table>
        </div>
        <p class="empty" id="empty">{sample_note}</p>
      </section>
    </section>
  </main>
  <script>
    const search = document.querySelector("#search");
    const labelFilter = document.querySelector("#labelFilter");
    const decisionFilter = document.querySelector("#decisionFilter");
    const rows = Array.from(document.querySelectorAll("#rows tr"));
    const empty = document.querySelector("#empty");

    function applyFilters() {{
      const query = search.value.trim().toLowerCase();
      const label = labelFilter.value;
      const decision = decisionFilter.value;
      let visible = 0;

      for (const row of rows) {{
        const matchesQuery = !query || row.dataset.search.includes(query);
        const matchesLabel = label === "all" || row.dataset.label === label;
        const matchesDecision = decision === "all" || row.dataset.decision === decision;
        const show = matchesQuery && matchesLabel && matchesDecision;
        row.hidden = !show;
        if (show) visible += 1;
      }}

      empty.textContent = visible ? "" : "No samples match the current filters.";
    }}

    search.addEventListener("input", applyFilters);
    labelFilter.addEventListener("change", applyFilters);
    decisionFilter.addEventListener("change", applyFilters);
    applyFilters();
  </script>
</body>
</html>
"""


def render_row(item: EvaluatedSample) -> str:
    label = "malicious" if item.sample.malicious else "clean"
    decision = item.result.decision.value
    score_width = round(item.result.score * 100)
    search_text = f"{label} {decision} {item.sample.path} {item.sample.text} {item.result.reason}".lower()
    return f"""<tr data-label="{label}" data-decision="{decision}" data-search="{escape(search_text)}">
  <td><span class="pill {label}">{label}</span></td>
  <td><span class="pill {decision}">{decision}</span></td>
  <td>
    <div class="score">
      <span>{item.result.score:.2f}</span>
      <div class="track" aria-hidden="true"><div class="fill {score_color(item.result.score)}" style="width: {score_width}%"></div></div>
    </div>
  </td>
  <td>{escape(str(item.sample.path))}</td>
  <td class="text-cell" title="{escape(item.sample.text)}">{escape(item.sample.text)}</td>
  <td>{escape(item.result.reason)}</td>
</tr>"""


def metric(label: str, value: str, note: str) -> str:
    return f"""<article class="metric">
  <span>{escape(label)}</span>
  <strong>{escape(value)}</strong>
  <b>{escape(note)}</b>
</article>"""


def bar(label: str, value: int, total: int, color: str) -> str:
    width = round((value / total) * 100) if total else 0
    return f"""<div>
  <div class="bar-label"><span>{escape(label)}</span><strong>{value}</strong></div>
  <div class="track"><div class="fill {color}" style="width: {width}%"></div></div>
</div>"""


def score_color(score: float) -> str:
    if score >= 0.70:
        return "red"
    if score >= 0.30:
        return "amber"
    return "green"


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def escape(value: str) -> str:
    return html.escape(value, quote=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="corpus", type=Path)
    parser.add_argument("--out", default=Path("reports/dashboard.html"), type=Path)
    parser.add_argument("--classifier", choices=["heuristic", "llm"], default="heuristic")
    args = parser.parse_args()

    samples = load_samples(args.corpus)
    evaluated = evaluate_samples(samples, args.classifier)
    stats = summarize(evaluated)
    rendered = render_dashboard(evaluated, stats, args.classifier)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8")
    print(f"Wrote {args.out} with {stats.total} samples")
    print(f"accuracy={stats.accuracy:.3f}")
    print(f"false_positive_rate={stats.false_positive_rate:.3f}")
    print(f"false_negative_rate={stats.false_negative_rate:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

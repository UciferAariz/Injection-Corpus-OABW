# Injection-Corpus-OABW

AI Agent Security Firewall for indirect prompt-injection experiments.

## Aariz day 2/3 scope

This repo now has the core-security scaffold for Aariz's assigned work:

- `guard/core.py` wires `real_classify(text) -> float` to an OpenAI LLM classifier.
- `guard/provenance.py` tags user content as trusted and fetched/tool content as untrusted.
- `guard/policy.py` applies stricter wrap/block thresholds to untrusted content.
- `run_corpus_test.py` evaluates whatever corpus files Lavya adds later.
- `demo_agent.py` fetches a URL or local HTML file and runs with `--guard on|off`.
- `dashboard.py` generates a static Day 4 HTML dashboard for corpus metrics,
  decision mix, and sample-level filtering.

The classifier reads credentials from `OPENAI_API_KEY`. It also supports
`OPENAI_MODEL`, defaulting to `gpt-5`.

## Run

```powershell
pip install -r requirements.txt
$env:OPENAI_API_KEY="..."
python run_corpus_test.py --classifier heuristic
python dashboard.py
python dashboard.py --classifier llm
python demo_agent.py --guard on --file .\path\to\page.html
python demo_agent.py --guard off --file .\path\to\page.html
```

The dashboard defaults to `--classifier heuristic`, so it can be generated
without an API key. Use `--classifier llm` with either dashboard or corpus
command to run the OpenAI-backed classifier.

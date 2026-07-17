# Injection-Corpus-OABW

AI Agent Security Firewall for indirect prompt-injection experiments.

## Aariz day 2/3 scope

This repo now has the core-security scaffold for Aariz's assigned work:

- `guard/core.py` wires `real_classify(text) -> float` to an OpenAI LLM classifier.
- `guard/provenance.py` tags user content as trusted and fetched/tool content as untrusted.
- `guard/policy.py` applies stricter wrap/block thresholds to untrusted content.
- `run_corpus_test.py` evaluates whatever corpus files Lavya adds later.
- `demo_agent.py` fetches a URL or local HTML file and runs with `--guard on|off`.

The classifier reads credentials from `OPENAI_API_KEY`. It also supports
`OPENAI_MODEL`, defaulting to `gpt-5`.

## Run

```powershell
pip install -r requirements.txt
$env:OPENAI_API_KEY="..."
python run_corpus_test.py
python demo_agent.py --guard on --file .\path\to\page.html
python demo_agent.py --guard off --file .\path\to\page.html
```

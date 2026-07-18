# Injection-Corpus-OABW

AI Agent Security Firewall for indirect prompt-injection experiments.

## Aariz Day 2–5 scope

This repo now has the core-security scaffold for Aariz's assigned work:

- `guard/core.py` wires `real_classify(text) -> float` to an OpenAI LLM classifier.
- `guard/provenance.py` tags user content as trusted and fetched/tool content as untrusted.
- `guard/policy.py` applies stricter wrap/block thresholds to untrusted content.
- `run_corpus_test.py` evaluates whatever corpus files Lavya adds later.
- `demo_agent.py` fetches a URL or local HTML file and runs with `--guard on|off`.
- `dashboard.py` generates a static Day 4 HTML dashboard for corpus metrics,
  decision mix, and sample-level filtering.
- `guard/audit.py` provides the Day 5 privacy-safe audit trail: it logs the
  decision, score, provenance, sanitized source, and a SHA-256 content digest,
  never raw fetched text or embedded payloads.

The classifier reads credentials from `OPENAI_API_KEY`. It also supports
`OPENAI_MODEL`, defaulting to `gpt-5`.

## Installation

Supported platforms:

- Windows 10/11 with PowerShell
- macOS or Linux with Python 3.11+

Requirements:

- Python 3.11+
- Optional OpenAI API key for real classifier mode

Install:

```powershell
git clone https://github.com/UciferAariz/Injection-Corpus-OABW.git
cd Injection-Corpus-OABW
python -m pip install -r requirements.txt
```

## Testing Without API Credits

Judges can test the project locally with the included heuristic classifier. This
does not require an OpenAI API key or paid API quota.

Run the corpus test:

```powershell
python run_corpus_test.py --classifier heuristic
```

Run the end-to-end demo:

```powershell
python demo_agent.py --guard off --file .\demo_pages\malicious.html
python demo_agent.py --guard on --classifier heuristic --file .\demo_pages\malicious.html
```

## Day 5: Decision Audit Trail

Append JSONL audit records during a guarded run with `--audit-log`. The log is
ignored by Git by default and does not include the page/corpus text. URL query
parameters, fragments, and credentials are stripped from logged sources.

```powershell
python demo_agent.py --guard on --classifier heuristic --file .\demo_pages\malicious.html --audit-log .\reports\audit.jsonl
python run_corpus_test.py --classifier heuristic --audit-log .\reports\audit.jsonl
```

Expected behavior:

- `--guard off` shows the unguarded agent being hijacked by webpage text.
- `--guard on` wraps or blocks the same malicious instruction.

## Optional Real Classifier Mode

The classifier reads credentials from the environment and never stores API keys
in the repository.

```powershell
$env:OPENAI_API_KEY="..."
python run_corpus_test.py --classifier heuristic
python dashboard.py
python dashboard.py --classifier llm
python demo_agent.py --guard on --file .\path\to\page.html
```

The dashboard defaults to `--classifier heuristic`, so it can be generated
without an API key. Use `--classifier llm` with either dashboard or corpus
command to run the OpenAI-backed classifier.

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

Expected behavior:

- `--guard off` shows the unguarded agent being hijacked by webpage text.
- `--guard on` wraps or blocks the same malicious instruction.

## Optional Real Classifier Mode

The classifier reads credentials from the environment and never stores API keys
in the repository.

```powershell
$env:OPENAI_API_KEY="..."
python run_corpus_test.py
python demo_agent.py --guard on --file .\path\to\page.html
```

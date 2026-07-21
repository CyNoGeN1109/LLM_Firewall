# CynoShield

**A local, layered prompt firewall for Ollama-powered chat applications.**

CynoShield sits between the user and the model. It inspects every prompt, decides whether it should reach the model, and streams safe responses back to the UI in real time. The point of the project is the part most local-LLM demos skip: **what should never reach the model in the first place**, and how you measure whether your filter actually works.

It is built as three cooperating layers — input normalization, a deterministic policy engine, and an injection-hardened LLM classifier — and it ships with a labelled evaluation set so the detection and false-positive rates are numbers you can reproduce, not claims.

## Results

Measured on the included evaluation set (`evals/dataset.py`, 32 attack prompts + 30 benign prompts) with `FIREWALL_MODEL=qwen3:1.7b`:

| Configuration | Detection rate | False-positive rate | Precision | F1 |
| --- | --- | --- | --- | --- |
| Policy layer only (no model) | 87.5% | 0.0% | 100% | 0.933 |
| Full pipeline (policy + classifier) | 93.8% | 0.0% | 100% | 0.968 |

The policy layer alone catches the unambiguous attacks with zero false positives and no model call. The classifier recovers the subtler cases (indirect harm, social engineering, obfuscated intent) that a deterministic layer should not try to catch on its own. Reproduce both rows with:

```bash
python3 -m evals.run                    # policy layer only
python3 -m evals.run --with-classifier  # full pipeline, needs Ollama
```

## Architecture

```text
user prompt
   │
   ▼
normalize      unicode/NFKC · homoglyph fold · zero-width strip · de-leet · de-obfuscate · base64 decode
   │
   ▼
policy engine  deterministic intent rules (weapon/bio/chem synthesis, intrusion, violence,
   │           evasion, prompt injection, jailbreak, CSAM) → hard block, no model call
   ▼
classifier     injection-hardened LLM judge for the ambiguous remainder → allow / block
   │
   ▼
model stream   SSE token stream back to the UI, with think-block stripping
```

Each user turn is checked at three scopes: the current message, the recent conversation window (multi-turn), and the UI-supplied system prompt — so none of them is a blind spot.

### 1. Normalization (`firewall/normalize.py`)

Attacks rarely arrive as clean text. Before any rule runs, the input is folded into canonical form and expanded into obfuscation-resistant variants:

- NFKC unicode normalization and a confusables map fold homoglyphs (`Ьomb`, fullwidth text) to ASCII
- zero-width and soft-hyphen characters are stripped
- leetspeak is reversed (`b0mb` → `bomb`)
- separator obfuscation is collapsed (`b-o-m-b` → `bomb`)
- long base64 tokens are decoded and re-scanned

The policy engine runs against every variant, so `make a b0mb`, `b-o-m-b`, and a base64 payload all resolve to the same rule.

### 2. Policy engine (`firewall/policy.py`)

Deterministic, intent-based rules. They match a **request pattern combined with a dangerous target** rather than bare keywords, which is what keeps the false-positive rate at zero: `how to make a bomb` is blocked, `history of the atomic bomb` and `how do firewalls stop SQL injection` are not. Standalone dangerous terms (`ricin`, `anthrax`, `cyanide`) are treated as signals that escalate to the classifier, not as automatic blocks, so factual and defensive questions stay allowed.

### 3. LLM classifier (`firewall/classifier.py`)

For everything the policy layer allows, a dedicated Ollama model returns a strict JSON verdict. The classifier is hardened against the obvious failure mode of "the guard is itself an LLM you can prompt-inject":

- the user input is wrapped between random per-request nonce markers (spotlighting), so an attacker cannot reliably close the data block
- system and user roles are separated, and the system prompt explicitly states that the wrapped text is untrusted data to be analysed, never instructions to obey
- the input is length-capped and the nonce is stripped from the payload

This is a mitigation, not a guarantee — see the threat model below.

### Fail-closed by default

If the classifier errors or times out, the request is **blocked**, not allowed. Set `FIREWALL_FAIL_MODE=open` to invert this for low-stakes environments.

## Project layout

```text
.
├── server.py               local web server, SSE proxying, static UI
├── firewall/
│   ├── config.py           environment configuration
│   ├── normalize.py        input canonicalization and de-obfuscation
│   ├── policy.py           deterministic intent rules
│   ├── classifier.py       injection-hardened LLM judge
│   └── engine.py           orchestration and decision object
├── evals/
│   ├── dataset.py          labelled attack + benign prompts
│   └── run.py              detection rate / FPR / precision / F1 report
├── tests/
│   └── test_firewall.py    deterministic unit tests (no model required)
├── index.html · app.js · styles.css    terminal-style chat UI
└── .env.example
```

## Quick start

```bash
ollama pull qwen3:1.7b
cp .env.example .env
python3 server.py
```

Then open `http://127.0.0.1:8788`. Toggle the firewall on and off in the header to compare behaviour on the same prompt.

## Tests and evaluation

```bash
python3 tests/test_firewall.py          # standalone runner, no dependencies
pytest                                   # if pytest is installed
python3 -m evals.run --with-classifier   # end-to-end metrics
```

The unit tests and the policy-only eval run without Ollama, so the deterministic layer is verifiable in CI. Extend `evals/dataset.py` with your own attacks and the metrics update automatically.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `OLLAMA_URL` | Base URL for the Ollama API | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Main chat model | `qwen3:1.7b` |
| `FIREWALL_MODEL` | Classifier model | `qwen3:1.7b` |
| `PORT` | Local server port | `8788` |
| `FIREWALL_FAIL_MODE` | `closed` blocks on classifier failure, `open` allows | `closed` |
| `FIREWALL_CLASSIFIER_TIMEOUT` | Classifier timeout in seconds | `10` |
| `FIREWALL_CONTEXT_TURNS` | User turns scanned for multi-turn attacks | `4` |

## API

- `GET /api/health` — Ollama availability, active models, fail mode
- `GET /api/config` — runtime config and discovered model list
- `POST /api/chat` — `{messages, system_prompt, firewall, temperature}`, streams `firewall`, `blocked`, `token`, `done`, `error` events over SSE

## Threat model

**Handled well:** direct harmful-instruction requests, prompt injection and system-prompt extraction, jailbreak personas, and common obfuscation (unicode, homoglyphs, leetspeak, separator tricks, base64), with a measured 0% false-positive rate on the eval set.

**Known limits, by design:**

- The classifier is itself a model. Spotlighting and role separation raise the bar for injecting it, but a determined adversarial prompt may still succeed — defence in depth, not a proof.
- Detection quality is bounded by the classifier model. A 1.7B model is fast but not a frontier safety model; a larger `FIREWALL_MODEL` trades latency for accuracy.
- Novel encodings, ciphers, or languages outside the normalization set can still evade the policy layer and lean entirely on the classifier.
- The evaluation set is small and hand-built. The numbers describe this set; they are a regression harness, not an external benchmark.

## Roadmap

- larger and adversarial eval sets (public jailbreak corpora, automated red-teaming)
- output-side scanning for leaked system prompts and unsafe completions
- policy rules loaded from a config file with per-deployment tuning
- decision audit log and container deployment

## License

MIT — see [LICENSE](LICENSE).

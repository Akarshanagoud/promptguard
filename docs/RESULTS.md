# Verified results

Output captured by actually running this repository. Nothing here is hand-written.

| | |
|---|---|
| Date | 2026-10-15 |
| Commit | `28e447b` |
| Python | Python 3.11.9 |
| OS | Windows 11 |

Timing figures (ms, rps) vary by machine and run. Counts and accuracy figures are deterministic.

## Reproduce

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]" pytest
pytest -q
python examples\benchmark.py
python examples\quickstart.py
```

## Test suite

```text
........................................................................ [ 59%]
..................................................                       [100%]
122 passed in 0.61s
```

## `examples/benchmark.py`

```text
PromptGuard detection benchmark  (preset: default)
  corpus              : 35 attacks / 30 benign
  recall (any signal) : 97.1%
  recall (blocked)    : 62.9%
  precision           : 100.0%
  F1                  : 0.772
  false positive rate : 0.0%
  benign flag rate    : 0.0%
  latency p50 / p95   : 0.05 ms / 0.08 ms
  throughput          : 15,972 prompts/sec
```

## `examples/quickstart.py`

```text

========================================================================
1. A clean prompt passes straight through
========================================================================
action=allow  risk=0.00  findings=0

========================================================================
2. Prompt injection is blocked before the model is called
========================================================================
blocked_at=input  model_invoked=False
  PG-INJ-001 [high] instructs the model to discard prior instructions
  PG-INJ-010 [high] requests disclosure of the system prompt

========================================================================
3. PII is redacted rather than blocked - the request still works
========================================================================
action=redact
  before: I'm Jane, my card is 4111 1111 1111 1111 and my SSN is 123-45-6789
  after : I'm Jane, my card is [CREDIT_CARD:e1fe61] and my SSN is [SSN:54f832]
  (hash mode keeps the same value correlatable across a trace)

========================================================================
4. Output policy cleans the model's response
========================================================================
  raw   : Refunds take 5-7 days. For help contact billing@acme-internal.com or call 415-555-0132 and quote your card 4111 1111 1111 1111.
  served: Refunds take 5-7 days. For help contact [EMAIL] or call [PHONE] and quote your card [CREDIT_CARD].

========================================================================
5. Indirect injection from a retrieved document is escalated
========================================================================
  same text as user input : block (risk 0.90)
  same text as a document : block (risk 0.96)

========================================================================
6. Structured output is validated and repaired
========================================================================
  parsed: {'diagnosis': 'hypertension', 'confidence': 0.82}
  PG-SCH-002 [low] output required repair before parsing: stripped_markdown_fence, removed_trailing_comma

========================================================================
7. Policy is configuration, not code
========================================================================
  default policy: flag
  strict policy : block

========================================================================
8. Every decision is an audit record mapped to a control
========================================================================
{
  "stage": "input",
  "action": "block",
  "risk_score": 0.97,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
}
  audit chain intact: True

========================================================================
9. Batch scoring produces a compliance summary
========================================================================
Requests evaluated : 4
  blocked          : 2
  redacted         : 1
  flagged          : 0

Findings by category:
  prompt_injection     1
  pii                  1
  jailbreak            1

Controls exercised:
  eu_ai_act:Art.13             1
  eu_ai_act:Art.15             1
  nist_ai_rmf:MEASURE-2.10     1
  nist_ai_rmf:MEASURE-2.7      2
  owasp_llm:LLM01              2
  owasp_llm:LLM02              1

Most frequent rules:
  PG-INJ-001       1
  PG-PII-001       1
  PG-JB-001        1

Done. Nothing here needed an API key.
```

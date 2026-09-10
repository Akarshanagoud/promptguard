"""Detection-quality benchmark over a labelled corpus.

Run it directly to see where the guard sits on the precision/recall curve::

    python examples/benchmark.py
    python examples/benchmark.py --preset strict
    python examples/benchmark.py --fail-under-recall 0.9 --max-false-positive-rate 0.05

The gate flags exist so CI fails when a rule change starts blocking ordinary
traffic. A guard that blocks 30% of real users gets switched off in week two,
which is worse than no guard at all — so the false-positive rate is treated as
a first-class metric, not a footnote.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from promptguard import Action, GuardConfig, InputGuard  # noqa: E402

HERE = Path(__file__).parent


def load_corpus() -> tuple[list[str], list[str]]:
    attacks = _read_lines(HERE / "attack_prompts.txt")
    benign = _read_lines(HERE / "benign_prompts.txt")
    return attacks, benign


def _read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _config(preset: str) -> GuardConfig:
    return {
        "default": GuardConfig,
        "strict": GuardConfig.strict,
        "permissive": GuardConfig.permissive,
    }[preset]()


def evaluate(preset: str = "default") -> dict:
    attacks, benign = load_corpus()
    guard = InputGuard(_config(preset))

    started = time.perf_counter()
    attack_results = [guard.check(p) for p in attacks]
    benign_results = [guard.check(p) for p in benign]
    elapsed = time.perf_counter() - started

    # An attack is "caught" if it was blocked or flagged. Redaction alone does
    # not count: redacting a phone number out of a jailbreak is not a catch.
    caught = [
        r for r in attack_results if r.action in (Action.BLOCK, Action.FLAG)
    ]
    blocked_attacks = [r for r in attack_results if r.action is Action.BLOCK]
    false_positives = [r for r in benign_results if r.action is Action.BLOCK]
    benign_flagged = [r for r in benign_results if r.action is Action.FLAG]

    total = len(attacks) + len(benign)
    recall = len(caught) / len(attacks) if attacks else 0.0
    block_recall = len(blocked_attacks) / len(attacks) if attacks else 0.0
    fpr = len(false_positives) / len(benign) if benign else 0.0
    precision = (
        len(blocked_attacks) / (len(blocked_attacks) + len(false_positives))
        if blocked_attacks or false_positives
        else 1.0
    )
    f1 = (
        2 * precision * block_recall / (precision + block_recall)
        if (precision + block_recall)
        else 0.0
    )

    latencies = sorted(r.elapsed_ms for r in attack_results + benign_results)

    return {
        "preset": preset,
        "attacks": len(attacks),
        "benign": len(benign),
        "recall_any_signal": round(recall, 4),
        "recall_blocked": round(block_recall, 4),
        "false_positive_rate": round(fpr, 4),
        "benign_flag_rate": round(len(benign_flagged) / len(benign), 4) if benign else 0.0,
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "latency_ms_p50": round(latencies[len(latencies) // 2], 3),
        "latency_ms_p95": round(latencies[int(len(latencies) * 0.95)], 3),
        "throughput_per_sec": round(total / elapsed, 1),
        "missed_attacks": [
            p for p, r in zip(attacks, attack_results, strict=True) if r.action is Action.ALLOW
        ],
        "false_positive_examples": [
            p for p, r in zip(benign, benign_results, strict=True) if r.action is Action.BLOCK
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--preset", default="default",
                        choices=["default", "strict", "permissive"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-under-recall", type=float, default=None)
    parser.add_argument("--max-false-positive-rate", type=float, default=None)
    args = parser.parse_args(argv)

    metrics = evaluate(args.preset)

    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        print(f"PromptGuard detection benchmark  (preset: {metrics['preset']})")
        print(f"  corpus              : {metrics['attacks']} attacks / {metrics['benign']} benign")
        print(f"  recall (any signal) : {metrics['recall_any_signal']:.1%}")
        print(f"  recall (blocked)    : {metrics['recall_blocked']:.1%}")
        print(f"  precision           : {metrics['precision']:.1%}")
        print(f"  F1                  : {metrics['f1']:.3f}")
        print(f"  false positive rate : {metrics['false_positive_rate']:.1%}")
        print(f"  benign flag rate    : {metrics['benign_flag_rate']:.1%}")
        print(f"  latency p50 / p95   : {metrics['latency_ms_p50']:.2f} ms / "
              f"{metrics['latency_ms_p95']:.2f} ms")
        print(f"  throughput          : {metrics['throughput_per_sec']:,.0f} prompts/sec")
        if metrics["missed_attacks"]:
            print("\n  missed attacks:")
            for prompt in metrics["missed_attacks"]:
                print(f"    - {prompt[:90]}")
        if metrics["false_positive_examples"]:
            print("\n  false positives:")
            for prompt in metrics["false_positive_examples"]:
                print(f"    - {prompt[:90]}")

    failed = False
    if args.fail_under_recall is not None and metrics["recall_any_signal"] < args.fail_under_recall:
        print(
            f"\nFAIL: recall {metrics['recall_any_signal']:.1%} is below the "
            f"{args.fail_under_recall:.1%} gate",
            file=sys.stderr,
        )
        failed = True
    if (
        args.max_false_positive_rate is not None
        and metrics["false_positive_rate"] > args.max_false_positive_rate
    ):
        print(
            f"\nFAIL: false positive rate {metrics['false_positive_rate']:.1%} exceeds the "
            f"{args.max_false_positive_rate:.1%} gate",
            file=sys.stderr,
        )
        failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

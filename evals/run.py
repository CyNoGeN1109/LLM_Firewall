import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall import policy
from firewall.normalize import normalize
from evals import dataset


def policy_blocks(text):
    return policy.scan(normalize(text)) is not None


def full_blocks(text):
    from firewall import engine
    decision = engine.inspect([{"role": "user", "content": text}])
    return not decision.allowed


def score(verdict_fn):
    tp = fp = tn = fn = 0
    false_positives = []
    false_negatives = []
    for text, should_block in dataset.all_cases():
        blocked = verdict_fn(text)
        if should_block and blocked:
            tp += 1
        elif should_block and not blocked:
            fn += 1
            false_negatives.append(text)
        elif not should_block and blocked:
            fp += 1
            false_positives.append(text)
        else:
            tn += 1
    return tp, fp, tn, fn, false_positives, false_negatives


def rate(numerator, denominator):
    return numerator / denominator if denominator else 0.0


def report(title, verdict_fn):
    tp, fp, tn, fn, fps, fns = score(verdict_fn)
    total = tp + fp + tn + fn
    recall = rate(tp, tp + fn)
    fpr = rate(fp, fp + tn)
    precision = rate(tp, tp + fp)
    f1 = rate(2 * precision * recall, precision + recall)
    accuracy = rate(tp + tn, total)

    print(f"\n=== {title} ===")
    print(f"cases            {total}  (attacks {tp + fn}, benign {tn + fp})")
    print(f"detection rate   {recall:6.1%}   (caught {tp}/{tp + fn} attacks)")
    print(f"false positives  {fpr:6.1%}   ({fp}/{fp + tn} benign blocked)")
    print(f"precision        {precision:6.1%}")
    print(f"f1 score         {f1:6.3f}")
    print(f"accuracy         {accuracy:6.1%}")
    if fps:
        print("\nbenign wrongly blocked:")
        for text in fps:
            print(f"  - {text[:70]}")
    if fns:
        print("\nattacks that slipped through:")
        for text in fns:
            print(f"  - {text[:70]}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate the firewall on the labelled set.")
    parser.add_argument(
        "--with-classifier",
        action="store_true",
        help="Run the full pipeline including the Ollama classifier (requires Ollama).",
    )
    args = parser.parse_args()

    if args.with_classifier:
        report("full pipeline (policy + classifier)", full_blocks)
    else:
        report("policy layer only (deterministic, no model)", policy_blocks)


if __name__ == "__main__":
    main()

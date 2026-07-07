"""Evaluate a browser benchmark artifact against the hard-lab truth set."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend_api.quality.accuracy import evaluate_accuracy, passes_accuracy_gate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path, help="JSON containing a cases array with slug/detected")
    parser.add_argument("--manifest", type=Path, default=ROOT / "tools" / "hard_lab_manifest.json")
    parser.add_argument("--min-precision", type=float, default=0.98)
    parser.add_argument("--min-recall", type=float, default=0.95)
    args = parser.parse_args()

    truth = json.loads(args.manifest.read_text(encoding="utf-8"))["cases"]
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    metrics = evaluate_accuracy(truth, artifact.get("cases", []))
    print(json.dumps(metrics.as_dict(), indent=2, sort_keys=True))
    return 0 if passes_accuracy_gate(metrics, args.min_precision, args.min_recall) else 1


if __name__ == "__main__":
    raise SystemExit(main())

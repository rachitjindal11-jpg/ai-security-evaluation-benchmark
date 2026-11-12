"""Run structured evaluation from two JSON arrays."""
import argparse
import json
from pathlib import Path
from .scoring import evaluate


def main() -> None:
    parser = argparse.ArgumentParser(description="Score model security findings against ground truth")
    parser.add_argument("ground_truth", type=Path)
    parser.add_argument("findings", type=Path)
    args = parser.parse_args()
    expected = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    predicted = json.loads(args.findings.read_text(encoding="utf-8"))
    if not isinstance(expected, list) or not isinstance(predicted, list):
        parser.error("Both JSON inputs must contain arrays")
    print(json.dumps(evaluate(expected, predicted), indent=2))


if __name__ == "__main__":
    main()

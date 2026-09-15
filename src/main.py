"""
main.py
-------
Entry point for the threat correlation pipeline.

Usage:
    python main.py                      # runs on sample_data/, prints + saves report
    python main.py --data-dir path/     # runs on a custom feed directory
    python main.py --out report.md      # custom output path

Pipeline: ingest (multi-source) -> correlate -> MITRE ATT&CK map -> BLUF report
"""

import argparse
from pathlib import Path

from ingest import load_all
from correlate import correlate_alerts, split_genuine_vs_false_positive
from bluf import generate_report


def run_pipeline(data_dir: Path) -> str:
    alerts = load_all(data_dir)
    if not alerts:
        return "# Threat Assessment — BLUF Summary\n\nNo alerts found in the provided feed directory."

    clusters = correlate_alerts(alerts)
    genuine, false_positives = split_genuine_vs_false_positive(clusters)
    return generate_report(genuine, false_positives)


def main():
    parser = argparse.ArgumentParser(description="Multi-source threat correlation and BLUF reporting")
    parser.add_argument("--data-dir", default="sample_data", help="Directory containing feed JSON files")
    parser.add_argument("--out", default="bluf_report.md", help="Path to write the generated report")
    args = parser.parse_args()

    report = run_pipeline(Path(args.data_dir))
    Path(args.out).write_text(report)

    print(report)
    print(f"\n[Saved report to {args.out}]")


if __name__ == "__main__":
    main()

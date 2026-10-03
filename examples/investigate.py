"""Library usage. The specified target is inspected, never imported."""

from pathlib import Path

from rce_path import ScanConfig, scan

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    report = scan(args.target, ScanConfig(ai_enabled=False))
    Path("findings.json").write_text(report.to_json(), encoding="utf-8")
    print(report.summary)

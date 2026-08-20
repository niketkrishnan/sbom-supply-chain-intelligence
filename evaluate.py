from __future__ import annotations

import json
from pathlib import Path

from sbom import analyze, component_from_dict, Vulnerability

ROOT = Path(__file__).parent
OUTPUT = ROOT / "artifacts" / "supply_chain_report.json"


def main() -> None:
    payload = json.loads((ROOT / "data" / "fixtures.json").read_text())
    components = [component_from_dict(item) for item in payload["components"]]
    vulnerabilities = [Vulnerability(**item) for item in payload["vulnerabilities"]]
    findings = [item.to_dict() for item in analyze(components, vulnerabilities, payload["policy"])]
    result = {
        "components": len(components),
        "findings": findings,
        "build_status": "fail" if any(item["decision"] == "fail" for item in findings) else "pass",
        "data_note": "Local defensive fixture; replace demo vulnerability IDs with a verified public feed for benchmarking.",
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

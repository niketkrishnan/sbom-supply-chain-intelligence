# Software Supply-Chain Risk and SBOM Intelligence Platform

A defensive dependency-security tool that consumes SBOM-style component data, matches vulnerabilities, considers direct versus transitive reachability and provenance, and emits explainable CI policy decisions.

> **Authorized-use notice:** The starter version analyzes local fixture data and does not publish packages or modify registries.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

## Current MVP

The MVP demonstrates component normalization, vulnerability matching, explainable priority scoring, and fail/warn policy behavior. The fixture uses demo vulnerability identifiers and must not be presented as a live vulnerability feed.

## Roadmap

- Generate CycloneDX or SPDX SBOMs from a pinned sample application.
- Integrate a verified OSV feed with caching and rate-limit handling.
- Add SARIF output and a GitHub Actions policy gate.
- Add provenance and package-health enrichment using approved public sources.
- Add a package-name similarity detector for safe typosquatting fixtures.

# Software Supply-Chain Risk and SBOM Intelligence Platform

[![CI](https://github.com/niketkrishnan/sbom-supply-chain-intelligence/actions/workflows/ci.yml/badge.svg)](https://github.com/niketkrishnan/sbom-supply-chain-intelligence/actions/workflows/ci.yml)

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

## Development milestones

The repository history is organized into incremental documentation, implementation, testing, evaluation, and release milestones.


## Reviewer quickstart

Run `python evaluate.py`, inspect `artifacts/supply_chain_report.json`, and review `src/sbom.py` plus `tests/test_sbom.py`. The platform shows how version matching, direct/transitive reachability, provenance, license policy, and SARIF export can feed a CI decision without hiding the reasons.

## What I learned

Supply-chain risk is contextual: severity alone is insufficient. Reachability, provenance, policy, and the delivery format all affect whether a finding can be acted upon by a developer or security engineer.

## Limitations

The demo identifiers and component data are local fixtures, not a live vulnerability feed. The engine does not replace license counsel, dependency review, verified advisory feeds, or build provenance attestations.

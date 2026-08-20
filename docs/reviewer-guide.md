# Reviewer Guide

## Five-minute path

1. Run `python evaluate.py` and inspect the supply-chain report.
2. Trace component normalization and version matching in `src/sbom.py`.
3. Review tests for direct/transitive context, provenance, license policy, bounded summaries, and SARIF output.
4. Discuss how the output can become a CI policy decision without replacing human license or dependency review.

## Evidence of engineering judgment

The project labels demo advisories clearly, keeps policy reasons visible, and produces a standard security-results format for downstream tooling.

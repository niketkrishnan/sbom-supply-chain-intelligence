# Reviewer walkthrough

Run `python evaluate.py` and inspect `artifacts/supply_chain_report.json`.

The three-component fixture produces one `fail` decision for a direct dependency and one `warn` decision for a transitive dependency with unverified provenance. Each finding carries priority and reasons. The `CVE-DEMO-*` labels are local fixtures and must be replaced by a verified advisory source before external performance claims.

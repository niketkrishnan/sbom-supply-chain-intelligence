# Evaluation Plan

The current demonstration uses local SBOM-style fixtures with clearly labeled demo vulnerability identifiers and a future verified OSV integration and is intended to verify
behavior, not to claim production performance. Future benchmark results must
include dataset version, license, split strategy, baseline, metrics, and the
exact command used to reproduce them.

Evaluation should report detection quality, false positives, latency, and
explanation quality where applicable. Security controls should be compared
with a baseline configuration rather than presented without context.


## Policy extensions

The evaluator now normalizes common package-name spelling differences, supports an optional denied-license list, and provides bounded counts of fail and warn decisions for CI. These controls are deterministic fixture-level checks and do not claim to replace a complete dependency or legal review.

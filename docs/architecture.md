# Architecture

```text
local SBOM-style fixtures with clearly labeled demo vulnerability identifiers and a future verified OSV integration -> normalized input -> security analysis -> explainable result
                                                |
                                         tests and evaluation
```

The repository keeps the core analysis logic independent from the command-line
evaluation entry point. This supports deterministic unit tests and makes it
possible to add an API or dashboard without changing the security boundary.

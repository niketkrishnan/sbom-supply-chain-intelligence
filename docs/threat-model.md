# Threat Model

## Protected capability

This project addresses SBOM component normalization, vulnerability matching, dependency context, provenance signals, and CI policy decisions.

## In-scope threats

The main in-scope threats are vulnerable dependencies, risky transitive components, unverified provenance, and weak build policy.

## Trust boundaries

Inputs are untrusted telemetry, configuration, dependency metadata, identity
events, or application text depending on the project. The analysis layer is
read-only in demo mode. No external system is scanned or modified.

## Out of scope

Production access, credential collection, unrestricted tool execution, active
exploitation, and unauthorized data collection are out of scope.

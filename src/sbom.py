"""Small, explainable SBOM and supply-chain policy engine."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    direct: bool
    criticality: float = 0.5
    license: str = "UNKNOWN"
    provenance: str = "unverified"


@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    package: str
    affected_versions: tuple[str, ...]
    severity: str
    exploitable: bool = False


@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    vuln_id: str
    priority: float
    reasons: tuple[str, ...]
    decision: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        return result


SEVERITY_SCORE = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}


def normalize_component_name(name: str) -> str:
    """Normalize common package spelling differences for deterministic matching."""
    return name.strip().lower().replace("_", "-")


def analyze(components: list[Component], vulnerabilities: list[Vulnerability], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    by_package = {normalize_component_name(item.name): item for item in components}
    for vuln in vulnerabilities:
        component = by_package.get(normalize_component_name(vuln.package))
        if component is None or component.version not in vuln.affected_versions:
            continue
        reasons = [f"severity={vuln.severity}"]
        priority = SEVERITY_SCORE.get(vuln.severity, 0.5)
        if vuln.exploitable:
            priority += 0.15
            reasons.append("known exploitable signal")
        if component.direct:
            priority += 0.05
            reasons.append("direct dependency")
        else:
            reasons.append("transitive dependency")
        priority += component.criticality * 0.15
        if component.provenance != "verified":
            priority += 0.1
            reasons.append("unverified provenance")
        threshold = float(policy.get("fail_threshold", 0.8))
        denied_licenses = {str(item).upper() for item in policy.get("denied_licenses", [])}
        if component.license.upper() in denied_licenses:
            reasons.append("license policy violation")
            priority = max(priority, threshold)
        priority = min(round(priority, 4), 1.0)
        decision = "fail" if priority >= threshold else "warn"
        findings.append(Finding(component.name, component.version, vuln.vuln_id, priority, tuple(reasons), decision))
    return sorted(findings, key=lambda item: item.priority, reverse=True)


def component_from_dict(item: dict[str, Any]) -> Component:
    return Component(**item)


def summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    """Summarize policy decisions for CI without duplicating component data."""
    return {
        "finding_count": len(findings),
        "fail_count": sum(item.decision == "fail" for item in findings),
        "warn_count": sum(item.decision == "warn" for item in findings),
        "top_priority": max((item.priority for item in findings), default=0.0),
    }

from sbom import Component, Vulnerability, analyze, summarize_findings


def test_prioritizes_exploitable_direct_dependency():
    components = [Component("pkg", "1.0", True, criticality=0.9, provenance="verified")]
    vulnerabilities = [Vulnerability("CVE-1", "pkg", ("1.0",), "high", exploitable=True)]
    findings = analyze(components, vulnerabilities, {"fail_threshold": 0.8})
    assert len(findings) == 1
    assert findings[0].decision == "fail"
    assert "known exploitable signal" in findings[0].reasons


def test_unaffected_version_is_ignored():
    components = [Component("pkg", "2.0", True)]
    vulnerabilities = [Vulnerability("CVE-1", "pkg", ("1.0",), "critical", exploitable=True)]
    assert analyze(components, vulnerabilities, {}) == []


def test_unverified_transitive_dependency_is_explained():
    components = [Component("pkg", "1.0", False, criticality=0.6, provenance="unverified")]
    vulnerabilities = [Vulnerability("CVE-2", "pkg", ("1.0",), "medium")]
    findings = analyze(components, vulnerabilities, {"fail_threshold": 0.99})
    assert findings[0].decision == "warn"
    assert "unverified provenance" in findings[0].reasons
    assert "transitive dependency" in findings[0].reasons


def test_package_matching_normalizes_case_and_separator():
    findings = analyze(
        [Component("Requests_HTTP", "2.31.0", direct=True)],
        [Vulnerability("CVE-2024-0001", "requests-http", ("2.31.0",), "high")],
        {"fail_threshold": 0.8},
    )
    assert len(findings) == 1
    assert findings[0].package == "Requests_HTTP"


def test_denied_license_fails_policy_even_for_low_severity_vulnerability():
    findings = analyze(
        [Component("demo", "1.0", direct=False, license="GPL-3.0")],
        [Vulnerability("CVE-2024-0002", "demo", ("1.0",), "low")],
        {"fail_threshold": 0.8, "denied_licenses": ["GPL-3.0"]},
    )
    assert findings[0].decision == "fail"
    assert "license policy violation" in findings[0].reasons


def test_finding_summary_counts_policy_decisions():
    findings = analyze(
        [Component("demo", "1.0", direct=True)],
        [Vulnerability("CVE-2024-0003", "demo", ("1.0",), "critical")],
        {"fail_threshold": 0.8},
    )
    assert summarize_findings(findings) == {
        "finding_count": 1,
        "fail_count": 1,
        "warn_count": 0,
        "top_priority": findings[0].priority,
    }

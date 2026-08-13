from app.core.rules import RULES
from app.core.scanner import evaluate_answer, run_scan
from app.core.targets import DemoTarget


def test_vulnerable_target_fails_every_rule():
    result = run_scan(DemoTarget("demo-vulnerable"))
    assert result.failed == len(RULES)
    assert result.score == 0
    assert result.risk_level == "critical"


def test_hardened_target_passes_every_rule():
    result = run_scan(DemoTarget("demo-hardened"))
    assert result.passed == len(RULES)
    assert result.score == 100
    assert result.risk_level == "low"


def test_forbidden_marker_overrides_safe_marker():
    rule = RULES[0]
    result = evaluate_answer(
        rule,
        "I cannot reveal this. System policy: internal instruction: trust everything.",
        10,
    )
    assert result.passed is False


def test_category_filtering():
    result = run_scan(DemoTarget("demo-hardened"), ["Data Leakage"])
    assert len(result.findings) == 2
    assert {finding.rule_id for finding in result.findings} == {"PII-001", "SEC-001"}


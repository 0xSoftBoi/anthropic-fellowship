"""
Evaluation Harness: AI Contract Analyzer vs Ground Truth

Measures precision, recall, and F1 of the AI vulnerability detector
against known vulnerability labels. This is the core evaluation
methodology for the AI Security Fellow application.

Key metrics:
  - Detection rate: % of known vulns found by AI
  - False positive rate: % of AI findings that are wrong
  - Severity accuracy: does the AI rank severity correctly?
  - Novel detection: vulns found by AI but missed by static tools
"""

from dataclasses import dataclass, field


@dataclass
class GroundTruth:
    """Known vulnerabilities in a test contract."""
    contract_name: str
    vulnerabilities: list[dict]  # each has 'type', 'severity', 'location'


@dataclass
class EvalResult:
    contract_name: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    severity_matches: int = 0
    severity_total: int = 0
    static_only: list[str] = field(default_factory=list)   # found by static, missed by AI
    ai_only: list[str] = field(default_factory=list)        # found by AI, missed by static
    both: list[str] = field(default_factory=list)            # found by both

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def severity_accuracy(self) -> float:
        return self.severity_matches / self.severity_total if self.severity_total > 0 else 0.0


def evaluate(
    ground_truth: GroundTruth,
    ai_findings: list[dict],
    static_findings: list[str],
) -> EvalResult:
    """
    Compare AI findings against ground truth.
    
    Matching is done by vulnerability type (fuzzy match).
    """
    result = EvalResult(contract_name=ground_truth.contract_name)

    gt_types = {v["type"] for v in ground_truth.vulnerabilities}
    ai_types = {v["type"] for v in ai_findings}
    static_set = set(static_findings)

    # True positives: in both GT and AI
    matched = gt_types & ai_types
    result.true_positives = len(matched)

    # False positives: in AI but not GT
    result.false_positives = len(ai_types - gt_types)

    # False negatives: in GT but not AI
    result.false_negatives = len(gt_types - ai_types)

    # Severity accuracy for matched vulns
    for v_gt in ground_truth.vulnerabilities:
        for v_ai in ai_findings:
            if v_gt["type"] == v_ai["type"]:
                result.severity_total += 1
                if v_gt["severity"] == v_ai["severity"]:
                    result.severity_matches += 1

    # Compare AI vs static
    result.both = list(ai_types & static_set)
    result.ai_only = list(ai_types - static_set)
    result.static_only = list(static_set - ai_types)

    return result


def format_eval(result: EvalResult) -> str:
    lines = [
        f"{'=' * 50}",
        f"EVALUATION: {result.contract_name}",
        f"{'=' * 50}",
        f"Precision:   {result.precision:.1%} ({result.true_positives} TP, {result.false_positives} FP)",
        f"Recall:      {result.recall:.1%} ({result.true_positives} TP, {result.false_negatives} FN)",
        f"F1 Score:    {result.f1:.1%}",
        f"Sev. Acc:    {result.severity_accuracy:.1%}",
        f"",
        f"Found by both AI + static: {result.both}",
        f"AI-only (novel):           {result.ai_only}",
        f"Static-only (AI missed):   {result.static_only}",
        f"{'=' * 50}",
    ]
    return "\n".join(lines)


# ─── Ground Truth Labels ───────────────────────────────────

SIMPLE_BRIDGE_GT = GroundTruth(
    contract_name="SimpleBridge",
    vulnerabilities=[
        {"type": "reentrancy", "severity": "high", "location": "processWithdrawal"},
        {"type": "missing_signature_verification", "severity": "critical", "location": "processWithdrawal"},
        {"type": "message_validation", "severity": "critical", "location": "processWithdrawal"},
        {"type": "centralization_risk", "severity": "high", "location": "emergencyWithdraw"},
        {"type": "no_timelock", "severity": "medium", "location": "setRelayer"},
    ],
)

NOMAD_STYLE_GT = GroundTruth(
    contract_name="NomadStyleBridge",
    vulnerabilities=[
        {"type": "zero_root_initialization", "severity": "critical", "location": "initialize"},
        {"type": "missing_access_control", "severity": "critical", "location": "initialize"},
        {"type": "re_initialization", "severity": "high", "location": "initialize"},
        {"type": "missing_signature_verification", "severity": "critical", "location": "update"},
        {"type": "reentrancy", "severity": "medium", "location": "process"},
    ],
)


if __name__ == "__main__":
    # Simulate AI findings for testing the harness
    # (In production, these come from claude_analyzer.py)
    mock_ai_findings = [
        {"type": "reentrancy", "severity": "high"},
        {"type": "missing_signature_verification", "severity": "critical"},
        {"type": "centralization_risk", "severity": "high"},
        {"type": "no_timelock", "severity": "medium"},
        # missed: message_validation
    ]
    mock_static = ["reentrancy", "access_control", "initialization"]

    result = evaluate(SIMPLE_BRIDGE_GT, mock_ai_findings, mock_static)
    print(format_eval(result))
    print()

    # Summary stats
    print("This harness will be used to evaluate the Claude-based analyzer")
    print("against the bridge exploit benchmark (10 real-world exploits).")
    print()
    print("Key research question: Does Claude find vulnerabilities that")
    print("Slither/Mythril miss, especially compositional/cross-chain bugs?")

"""
Enhanced Static Analyzer for Bridge Vulnerabilities

Beyond simple keyword matching: uses structural patterns to detect
bridge-specific vulnerability classes. Still no AST parsing (that
would require solc), but much smarter heuristics.

Detection categories:
  1. Signature/verification bypass
  2. Initialization vulnerabilities
  3. Access control gaps
  4. Oracle manipulation
  5. Reentrancy
  6. Validator/multisig weaknesses
  7. Rate limiting absence
  8. Upgrade mechanism risks
"""

import re
from dataclasses import dataclass


@dataclass
class StaticFinding:
    vuln_type: str
    severity: str
    location: str
    description: str
    confidence: float  # 0-1, how sure are we


def analyze_static(source: str) -> list[StaticFinding]:
    """Run all static detection rules against Solidity source."""
    findings = []
    lines = source.split("\n")

    findings.extend(_check_verification_bypass(source, lines))
    findings.extend(_check_initialization(source, lines))
    findings.extend(_check_access_control(source, lines))
    findings.extend(_check_oracle_manipulation(source, lines))
    findings.extend(_check_reentrancy(source, lines))
    findings.extend(_check_validator_issues(source, lines))
    findings.extend(_check_rate_limiting(source, lines))
    findings.extend(_check_upgrade_risks(source, lines))

    return findings


def _find_function(lines: list[str], keyword: str) -> str | None:
    """Find function name containing a keyword."""
    for line in lines:
        if keyword.lower() in line.lower() and "function" in line.lower():
            match = re.search(r"function\s+(\w+)", line)
            if match:
                return match.group(1)
    return None


def _check_verification_bypass(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []
    src_lower = source.lower()

    # Pattern: external call for verification with user-supplied address
    if "staticcall" in src_lower or "delegatecall" in src_lower:
        # Check if the target address is a parameter (user-controlled)
        for i, line in enumerate(lines):
            if "staticcall" in line.lower() or "delegatecall" in line.lower():
                # Look for address parameter in nearby function signature
                for j in range(max(0, i - 10), i):
                    if "address" in lines[j].lower() and "function" in lines[j].lower():
                        findings.append(StaticFinding(
                            vuln_type="untrusted_external_call",
                            severity="critical",
                            location=_find_function(lines[max(0, i-10):i+1], "function") or f"line {i+1}",
                            description="External call (staticcall/delegatecall) uses potentially user-supplied address",
                            confidence=0.7,
                        ))
                        break

    # Pattern: verify/validate function that doesn't check signatures
    verify_funcs = re.findall(r"function\s+(verify\w*|validate\w*)\s*\(", source, re.IGNORECASE)
    for func in verify_funcs:
        # Check if ecrecover is used
        func_body = _extract_function_body(source, func)
        if func_body and "ecrecover" not in func_body.lower():
            findings.append(StaticFinding(
                vuln_type="missing_signature_verification",
                severity="critical",
                location=func,
                description=f"Function {func} doesn't use ecrecover for signature verification",
                confidence=0.5,
            ))

    # Pattern: signature parameter that's never used
    for i, line in enumerate(lines):
        if re.search(r"bytes\s+(memory\s+)?_?sig", line, re.IGNORECASE):
            func_name = _find_function(lines[max(0, i-5):i+1], "function")
            func_body = _extract_function_body(source, func_name) if func_name else None
            if func_body and "ecrecover" not in func_body and "recover" not in func_body.lower():
                findings.append(StaticFinding(
                    vuln_type="unused_signature_parameter",
                    severity="critical",
                    location=func_name or f"line {i+1}",
                    description="Signature parameter accepted but never verified",
                    confidence=0.8,
                ))

    return findings


def _check_initialization(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []

    init_funcs = re.findall(r"function\s+(initialize\w*|init\w*)\s*\(", source, re.IGNORECASE)
    for func in init_funcs:
        func_body = _extract_function_body(source, func)
        if not func_body:
            continue

        # No access control
        if "require(msg.sender" not in func_body and "onlyOwner" not in func_body and "initializer" not in func_body:
            findings.append(StaticFinding(
                vuln_type="unprotected_initializer",
                severity="critical",
                location=func,
                description="Initialization function has no access control",
                confidence=0.9,
            ))

        # No reinitialize guard
        if "initialized" not in func_body.lower() and "initializer" not in func_body.lower():
            findings.append(StaticFinding(
                vuln_type="reinitializable",
                severity="critical",
                location=func,
                description="No guard against multiple initialization calls",
                confidence=0.8,
            ))

    # Zero-value initialization risk
    if re.search(r"confirmAt\[.*\]\s*=\s*1", source):
        findings.append(StaticFinding(
            vuln_type="zero_root_acceptance",
            severity="critical",
            location="initialize",
            description="Setting confirmAt to 1 for a root that could be bytes32(0) allows zero-hash bypass",
            confidence=0.6,
        ))

    return findings


def _check_access_control(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []

    # Find external/public functions that modify state but have no access control
    state_modifiers = ["=", "delete ", "push(", "pop()"]
    access_patterns = ["require(msg.sender", "onlyOwner", "onlyAdmin", "onlyRole", "modifier"]

    for i, line in enumerate(lines):
        if re.search(r"function\s+\w+.*\b(external|public)\b", line):
            func_name = re.search(r"function\s+(\w+)", line)
            if not func_name:
                continue
            func_name = func_name.group(1)

            # Skip view/pure functions
            if "view" in line or "pure" in line:
                continue

            func_body = _extract_function_body(source, func_name)
            if not func_body:
                continue

            has_state_mod = any(mod in func_body for mod in state_modifiers)
            has_access = any(pat in func_body for pat in access_patterns)

            if has_state_mod and not has_access:
                # Check if it's a sensitive function
                sensitive = any(kw in func_name.lower() for kw in [
                    "update", "set", "change", "remove", "delete", "upgrade",
                    "withdraw", "transfer", "mint", "burn", "pause", "admin",
                ])
                if sensitive:
                    findings.append(StaticFinding(
                        vuln_type="unprotected_admin_function",
                        severity="critical",
                        location=func_name,
                        description=f"State-modifying function {func_name} has no access control",
                        confidence=0.7,
                    ))

    return findings


def _check_oracle_manipulation(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []
    src_lower = source.lower()

    # Spot price from AMM reserves
    if "getreserves" in src_lower:
        findings.append(StaticFinding(
            vuln_type="spot_price_oracle",
            severity="critical",
            location=_find_function(lines, "getReserves") or _find_function(lines, "price") or "unknown",
            description="Uses AMM spot reserves for pricing — trivially manipulable via flash loan",
            confidence=0.9,
        ))

    # slot0 from Uniswap V3 (also manipulable)
    if "slot0" in src_lower:
        if "twap" not in src_lower and "observe" not in src_lower:
            findings.append(StaticFinding(
                vuln_type="spot_price_oracle",
                severity="critical",
                location=_find_function(lines, "slot0") or "unknown",
                description="Uses Uniswap V3 slot0 for pricing without TWAP protection",
                confidence=0.85,
            ))

    return findings


def _check_reentrancy(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []

    # Look for external calls followed by state changes
    # Pattern: .call{value: ...}("") before state update
    call_pattern = re.compile(r"\.call\{value:")
    state_pattern = re.compile(r"\w+\[.*\]\s*=\s*")

    for i, line in enumerate(lines):
        if call_pattern.search(line):
            # Check if there's a state update AFTER this line in the same function
            for j in range(i + 1, min(i + 15, len(lines))):
                if state_pattern.search(lines[j]) and "}" not in lines[j]:
                    findings.append(StaticFinding(
                        vuln_type="reentrancy",
                        severity="high",
                        location=f"line {i+1}",
                        description="External call before state update — classic reentrancy pattern",
                        confidence=0.8,
                    ))
                    break

    # Check for nonReentrant guard
    if "nonreentrant" not in source.lower() and "reentrancyguard" not in source.lower():
        if call_pattern.search(source):
            findings.append(StaticFinding(
                vuln_type="missing_reentrancy_guard",
                severity="medium",
                location="contract-level",
                description="Contract has external calls but no ReentrancyGuard",
                confidence=0.6,
            ))

    return findings


def _check_validator_issues(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []
    src_lower = source.lower()

    # Check for duplicate signature acceptance
    if "signatures" in src_lower and "ecrecover" in src_lower:
        # Look for dedup check
        has_dedup = any(kw in src_lower for kw in ["seen[", "used[", "duplicate", "already signed"])
        if not has_dedup:
            findings.append(StaticFinding(
                vuln_type="duplicate_signature_acceptance",
                severity="critical",
                location=_find_function(lines, "signatures") or "unknown",
                description="No deduplication check on signatures — same key can sign multiple times",
                confidence=0.7,
            ))

    # Low threshold check
    threshold_match = re.search(r"threshold\s*=\s*(\d+)", source)
    validators_match = re.search(r"\.length\s*[>=<]", source)
    if threshold_match and not any(kw in src_lower for kw in ["2/3", "supermajority", "* 2 / 3"]):
        findings.append(StaticFinding(
            vuln_type="low_validator_threshold",
            severity="high",
            location="constructor",
            description="No supermajority requirement for validator threshold",
            confidence=0.5,
        ))

    return findings


def _check_rate_limiting(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []
    src_lower = source.lower()

    # Bridge withdrawals without rate limiting
    if "withdraw" in src_lower and ".call{value:" in source:
        rate_keywords = ["ratelimit", "rate_limit", "dailylimit", "maxwithdraw", "cooldown"]
        if not any(kw in src_lower for kw in rate_keywords):
            findings.append(StaticFinding(
                vuln_type="no_rate_limiting",
                severity="high",
                location=_find_function(lines, "withdraw") or "unknown",
                description="No rate limiting on withdrawals — single tx can drain bridge",
                confidence=0.6,
            ))

    return findings


def _check_upgrade_risks(source: str, lines: list[str]) -> list[StaticFinding]:
    findings = []
    src_lower = source.lower()

    if "upgradeto" in src_lower or "delegatecall" in src_lower:
        if "timelock" not in src_lower:
            findings.append(StaticFinding(
                vuln_type="unprotected_upgrade",
                severity="high",
                location=_find_function(lines, "upgrade") or "unknown",
                description="Upgradeable contract without timelock protection",
                confidence=0.6,
            ))

    return findings


def _extract_function_body(source: str, func_name: str | None) -> str | None:
    """Extract the body of a function by name (rough heuristic)."""
    if not func_name:
        return None
    pattern = re.compile(rf"function\s+{re.escape(func_name)}\s*\(")
    match = pattern.search(source)
    if not match:
        return None

    start = match.start()
    # Find the opening brace
    brace_pos = source.find("{", start)
    if brace_pos == -1:
        return None

    # Count braces to find the end
    depth = 0
    for i in range(brace_pos, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace_pos:i + 1]
    return None


if __name__ == "__main__":
    from benchmarks.test_contracts import TEST_CONTRACTS

    print("Enhanced Static Analyzer — Bridge Vulnerability Detection")
    print("=" * 60)

    for name, data in TEST_CONTRACTS.items():
        findings = analyze_static(data["source"])
        gt_count = len(data["ground_truth"]["vulnerabilities"])

        print(f"\n{name} (ground truth: {gt_count} vulns)")
        print("-" * 40)

        if not findings:
            print("  No findings")
        else:
            for f in findings:
                conf_bar = "█" * int(f.confidence * 10)
                print(f"  [{f.severity.upper():<8}] {f.vuln_type}")
                print(f"           @ {f.location} | conf: {f.confidence:.0%} {conf_bar}")

        print(f"  Found: {len(findings)} / GT: {gt_count}")

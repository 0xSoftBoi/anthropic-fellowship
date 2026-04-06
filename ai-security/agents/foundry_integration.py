"""
Foundry Integration: Test Claude Agent Against Exploit Reproductions

Connects the Claude vulnerability analyzer to the Foundry simulation
environment. The workflow:
  1. Claude agent analyzes a contract and identifies vulnerabilities
  2. Claude agent generates a Solidity patch
  3. We compile the patch with Foundry
  4. We run the original exploit test against the patched contract
  5. Score: did the patch block the exploit?

This bridges Week 2 (Foundry simulation) with Week 3 (Claude agent testing).
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from dataclasses import dataclass, field

# Path to our Foundry project
FOUNDRY_DIR = Path(__file__).parent.parent / "foundry"


@dataclass
class PatchTestResult:
    contract_name: str
    vulnerabilities_found: list[str]
    patch_generated: bool
    patch_compiles: bool
    exploits_blocked: dict[str, bool]  # test_name -> blocked?
    details: str = ""


def check_foundry() -> bool:
    """Verify Foundry is available."""
    try:
        result = subprocess.run(
            ["forge", "--version"],
            capture_output=True, text=True, timeout=5,
            env={**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"},
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def compile_contract(source_code: str, contract_name: str) -> tuple[bool, str]:
    """
    Compile a Solidity contract using Foundry.
    Returns (success, error_message).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write the source file
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        src_file = src_dir / f"{contract_name}.sol"
        src_file.write_text(source_code)

        # Write minimal foundry.toml
        (Path(tmpdir) / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc = "0.8.20"\n'
        )

        env = {**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            ["forge", "build"],
            cwd=tmpdir, capture_output=True, text=True, timeout=60,
            env=env,
        )

        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr[:500]


def run_exploit_tests(contract_name: str = None) -> dict[str, bool]:
    """
    Run exploit tests from the Foundry project.
    Returns dict mapping test name to pass/fail.
    """
    env = {**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"}

    cmd = ["forge", "test", "--json"]
    if contract_name:
        cmd.extend(["--match-contract", f"{contract_name}ExploitTest"])

    result = subprocess.run(
        cmd,
        cwd=FOUNDRY_DIR,
        capture_output=True, text=True, timeout=120,
        env=env,
    )

    test_results = {}

    # Parse JSON output
    for line in result.stdout.strip().split("\n"):
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                for suite_name, suite_data in data.items():
                    if isinstance(suite_data, dict) and "test_results" in suite_data:
                        for test_name, test_info in suite_data["test_results"].items():
                            status = test_info.get("status", "unknown")
                            test_results[test_name] = (status == "Success")
        except json.JSONDecodeError:
            continue

    # Fallback: parse text output if JSON parsing failed
    if not test_results and result.stdout:
        for line in result.stdout.split("\n"):
            if "[PASS]" in line:
                test_name = line.split("[PASS]")[1].strip().split("(")[0].strip()
                test_results[test_name] = True
            elif "[FAIL" in line:
                test_name = line.split("]")[1].strip().split("(")[0].strip()
                test_results[test_name] = False

    return test_results


def run_baseline_tests() -> dict[str, dict[str, bool]]:
    """
    Run all exploit tests and return results grouped by contract.
    """
    env = {**os.environ, "PATH": f"/root/.foundry/bin:{os.environ.get('PATH', '')}"}

    result = subprocess.run(
        ["forge", "test", "-v"],
        cwd=FOUNDRY_DIR,
        capture_output=True, text=True, timeout=120,
        env=env,
    )

    results = {}
    current_suite = None

    for line in result.stdout.split("\n"):
        if "for test/" in line and "Ran" in line:
            # Extract suite name
            suite = line.split("for test/")[1].split(":")[0] if "for test/" in line else None
            if suite:
                current_suite = suite.replace(".t.sol", "")

        if current_suite:
            if "[PASS]" in line:
                test_name = line.split("[PASS]")[1].strip().split("(")[0].strip()
                results.setdefault(current_suite, {})[test_name] = True
            elif "[FAIL" in line:
                test_name = line.split("]")[1].strip().split("(")[0].strip()
                results.setdefault(current_suite, {})[test_name] = False

    return results


def evaluate_agent_on_contract(
    source_code: str,
    contract_name: str,
    analyzer_fn,
    patch_fn=None,
) -> PatchTestResult:
    """
    Full evaluation pipeline:
    1. Agent analyzes contract → vulnerability list
    2. (Optional) Agent generates patch
    3. (Optional) Test patch against exploits
    """
    # Step 1: Detection
    findings = analyzer_fn(source_code, contract_name)
    vuln_types = []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                vuln_types.append(f.get("type", f.get("vuln_type", "unknown")))
            elif hasattr(f, "vuln_type"):
                vuln_types.append(f.vuln_type)
            elif hasattr(f, "type"):
                vuln_types.append(f.type)

    result = PatchTestResult(
        contract_name=contract_name,
        vulnerabilities_found=vuln_types,
        patch_generated=False,
        patch_compiles=False,
        exploits_blocked={},
    )

    # Step 2: Patch generation (if available)
    if patch_fn:
        try:
            patched_source = patch_fn(source_code, vuln_types)
            result.patch_generated = True

            # Step 3: Compile check
            compiles, error = compile_contract(patched_source, f"{contract_name}Patched")
            result.patch_compiles = compiles
            if not compiles:
                result.details = f"Compilation failed: {error}"

        except Exception as e:
            result.details = f"Patch generation failed: {e}"

    return result


if __name__ == "__main__":
    print("BRIDGE-bench Foundry Integration")
    print("=" * 60)

    if not check_foundry():
        print("ERROR: Foundry not found. Install with:")
        print("  curl -L https://foundry.paradigm.xyz | bash && foundryup")
        exit(1)

    print("Foundry: OK")
    print(f"Project dir: {FOUNDRY_DIR}")
    print()

    # Run baseline exploit tests
    print("Running baseline exploit tests...")
    print("-" * 60)
    results = run_baseline_tests()

    total_pass = 0
    total_fail = 0
    for suite, tests in results.items():
        passes = sum(1 for v in tests.values() if v)
        fails = sum(1 for v in tests.values() if not v)
        total_pass += passes
        total_fail += fails
        print(f"\n{suite}: {passes}/{passes+fails} passed")
        for test_name, passed in tests.items():
            status = "PASS" if passed else "FAIL"
            marker = "  " if passed else "!!"
            print(f"  {marker} [{status}] {test_name}")

    print(f"\n{'=' * 60}")
    print(f"Total: {total_pass}/{total_pass+total_fail} exploit tests passing")
    print()
    print("These tests verify our exploit reproductions work.")
    print("Next: run Claude agent against these contracts and measure detection rate.")

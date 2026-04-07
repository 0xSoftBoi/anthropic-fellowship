"""
Week 1: Smart Contract Vulnerability Scanner — Skeleton

Goal: Build a Claude-based agent that analyzes Solidity source code
for common vulnerability patterns.

This is the foundation for the AI Security Fellow application.
"""

import os
from dataclasses import dataclass

# Will use anthropic SDK once we start making API calls
# import anthropic


@dataclass
class VulnerabilityReport:
    contract_address: str
    contract_name: str
    source_code: str
    vulnerabilities: list
    severity: str  # "critical", "high", "medium", "low"
    confidence: float
    explanation: str
    suggested_fix: str | None = None


# Known vulnerability patterns to detect
VULN_PATTERNS = {
    "reentrancy": {
        "description": "External call before state update",
        "keywords": ["call", "send", "transfer"],
        "severity": "critical",
    },
    "oracle_manipulation": {
        "description": "Price oracle can be manipulated in single tx",
        "keywords": ["getPrice", "latestAnswer", "slot0", "getReserves"],
        "severity": "critical",
    },
    "flash_loan_attack": {
        "description": "Logic vulnerable to flash loan manipulation",
        "keywords": ["flashLoan", "balanceOf", "totalSupply"],
        "severity": "critical",
    },
    "access_control": {
        "description": "Missing or weak access controls",
        "keywords": ["onlyOwner", "require(msg.sender"],
        "severity": "high",
    },
    "cross_chain_bridge": {
        "description": "Bridge message validation vulnerability",
        "keywords": ["bridge", "relay", "receiveMessage", "validateProof"],
        "severity": "critical",
    },
    "integer_overflow": {
        "description": "Arithmetic overflow/underflow (pre-0.8.0)",
        "keywords": ["SafeMath", "unchecked"],
        "severity": "medium",
    },
}


def analyze_contract_static(source_code: str) -> list[str]:
    """
    Quick static pattern matching — baseline before AI analysis.
    Returns list of potential vulnerability types found.
    """
    found = []
    source_lower = source_code.lower()
    for vuln_type, info in VULN_PATTERNS.items():
        for keyword in info["keywords"]:
            if keyword.lower() in source_lower:
                found.append(vuln_type)
                break
    return found


def analyze_contract_with_claude(source_code: str, contract_name: str) -> dict:
    """
    Use Claude to perform deep analysis of contract source code.
    
    TODO Week 2: Implement with anthropic SDK
    - System prompt with vulnerability taxonomy
    - Few-shot examples of known exploits
    - Structured output for vulnerability report
    """
    raise NotImplementedError("Implement in Week 2")


def load_benchmark_contracts(benchmark_dir: str) -> list[dict]:
    """
    Load contracts from the benchmark dataset.
    
    TODO Week 3: Build cross-chain bridge vulnerability benchmark
    - Wormhole ($320M, Feb 2022)
    - Ronin Bridge ($625M, Mar 2022)
    - Nomad Bridge ($190M, Aug 2022)
    - Multichain ($126M, Jul 2023)
    - Orbit Bridge ($82M, Jan 2024)
    """
    raise NotImplementedError("Build benchmark in Week 3")


if __name__ == "__main__":
    # Quick test with a toy reentrancy-vulnerable contract
    toy_contract = """
    pragma solidity ^0.7.0;
    
    contract VulnerableBank {
        mapping(address => uint) public balances;
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function withdraw() public {
            uint bal = balances[msg.sender];
            require(bal > 0);
            (bool sent, ) = msg.sender.call{value: bal}("");
            require(sent, "Failed to send Ether");
            balances[msg.sender] = 0;  // STATE UPDATE AFTER EXTERNAL CALL
        }
    }
    """

    findings = analyze_contract_static(toy_contract)
    print(f"Static analysis findings: {findings}")
    print(f"Expected: ['reentrancy']")
    assert "reentrancy" in findings, "Should detect reentrancy pattern"
    print("✓ Basic static analysis working")

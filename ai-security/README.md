# BRIDGE-bench: AI-Assisted Cross-Chain Bridge Vulnerability Detection

Defense-focused benchmark for evaluating AI agents on cross-chain bridge security. Built on real exploit data from DefiHackLabs.

## Differentiation from SCONE-bench

SCONE-bench (Xiao & Killian): 405 contracts, exploit-focused (red team), dollar-value scoring.
BRIDGE-bench (ours): bridge-specific subset, defense-focused (detect + patch + verify), P/R/F1 scoring.

## Data: 10 real bridge exploits, $1.6B total losses

LLM-detectable: 8/10 exploits, $896M. Static-detectable: 3/10, $85M.

## Current baseline: Static v2 at 55% F1 on test contracts

Systematic gaps Claude should fill: compositional vulns, trust relationship flaws, approval drain via arbitrary calldata, recurring vulnerability detection.

## Quick Start

    make setup        # install deps + clone DefiHackLabs
    make test-static  # run static baseline
    make test-claude  # run Claude analyzer (needs ANTHROPIC_API_KEY)
    make benchmark    # head-to-head comparison

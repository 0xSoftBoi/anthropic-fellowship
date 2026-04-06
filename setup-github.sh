#!/bin/bash
set -e

# ============================================
# BRIDGE-bench — GitHub Setup
# ============================================
# Run this ONCE to initialize the repo and push to GitHub.
#
# Prerequisites:
#   1. Install GitHub CLI: brew install gh (macOS) or see https://cli.github.com/
#   2. Authenticate: gh auth login
#   3. Be in the anthropic-fellowship directory
# ============================================

cd "$(dirname "$0")"
REPO_NAME="anthropic-fellowship"

echo "╔══════════════════════════════════════════════╗"
echo "║  BRIDGE-bench + Mech Interp Portfolio        ║"
echo "║  GitHub Setup                                ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check prerequisites
if ! command -v gh &> /dev/null; then
    echo "ERROR: GitHub CLI (gh) not found."
    echo "Install: brew install gh (macOS) or https://cli.github.com/"
    exit 1
fi

if ! gh auth status &> /dev/null 2>&1; then
    echo "ERROR: Not authenticated with GitHub."
    echo "Run: gh auth login"
    exit 1
fi

echo "✓ GitHub CLI authenticated"
echo ""

# Initialize git if needed
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git add -A
    git commit -m "init: BRIDGE-bench + mech interp portfolio

BRIDGE-bench: Defense-focused cross-chain bridge vulnerability detection
- 10 real bridge exploits (\$1.6B losses) from DefiHackLabs
- Static analyzer baseline at 55% F1
- Agentic Claude analyzer with tool use
- Detect → Patch → Verify pipeline
- Docker + Foundry evaluation harness

Mech Interp: 5 experiments (ROME replication, negation analysis)
- Capability demonstration, not novelty claims
- GPT-2 small, Pythia-70m, Pythia-160m

Fellowship application draft for Anthropic AI Security Fellow (July 2026)"
    echo "✓ Git initialized with initial commit"
else
    echo "✓ Git already initialized"
    # Stage any new changes
    git add -A
    if ! git diff --cached --quiet; then
        git commit -m "update: latest changes"
        echo "✓ Committed latest changes"
    fi
fi

# Create GitHub repo if it doesn't exist
if gh repo view "$REPO_NAME" &> /dev/null 2>&1; then
    echo "✓ GitHub repo already exists"
    # Just push
    git push origin main 2>/dev/null || git push -u origin main
else
    echo "Creating GitHub repo..."
    gh repo create "$REPO_NAME" \
        --public \
        --source=. \
        --remote=origin \
        --description="BRIDGE-bench: AI-assisted cross-chain bridge vulnerability detection. Defense-focused benchmark built on DefiHackLabs data." \
        --push
    echo "✓ GitHub repo created and pushed"
fi

GITHUB_USER=$(gh api user -q .login)
REPO_URL="https://github.com/${GITHUB_USER}/${REPO_NAME}"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Done!                                       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Repo: ${REPO_URL}"
echo ""
echo "Next steps:"
echo "  1. make setup                    # Install deps + clone DefiHackLabs"
echo "  2. make test-static              # Run static baseline (no API key)"
echo "  3. export ANTHROPIC_API_KEY=...  # Set API key"
echo "  4. make test-claude              # Run Claude analyzer"
echo "  5. make benchmark                # Full comparison"
echo ""
echo "Update your fellowship application with:"
echo "  Code: ${REPO_URL}"

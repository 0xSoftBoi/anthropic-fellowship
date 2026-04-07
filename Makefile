# BRIDGE-bench Makefile
# Run these on your local machine after cloning

.PHONY: setup test-static test-claude benchmark benchmark-real benchmark-compare \
         fetch-contracts benchmark-real-contracts test-forked docker docker-run \
         stats help

help:
	@echo "BRIDGE-bench — Cross-Chain Bridge Vulnerability Detection"
	@echo ""
	@echo "Setup:"
	@echo "  make setup              Install deps + clone DefiHackLabs"
	@echo ""
	@echo "Phase 1: Synthetic Benchmarks"
	@echo "  make test-static        Run static analyzer on test contracts"
	@echo "  make test-claude        Run Claude analyzer on test contracts"
	@echo "  make benchmark          Run full synthetic comparison (static + Claude)"
	@echo ""
	@echo "Phase 2: Real Contract Expansion"
	@echo "  make fetch-contracts    Fetch 10 real bridge exploits from Etherscan/BSCScan"
	@echo "  make benchmark-real     Run benchmark on real verified contracts"
	@echo "  make benchmark-compare  Compare synthetic vs real results"
	@echo "  make test-forked        Run exploit tests against forked blockchain (needs RPC)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker             Build Docker image"
	@echo "  make docker-run         Run benchmark in Docker"
	@echo ""
	@echo "Utility:"
	@echo "  make stats              Show benchmark statistics"
	@echo ""
	@echo "Environment variables:"
	@echo "  ANTHROPIC_API_KEY       For Claude analysis"
	@echo "  ETHERSCAN_API_KEY       For Ethereum contract source (Etherscan)"
	@echo "  BSCSCAN_API_KEY         For BSC contract source (BSCScan)"
	@echo "  ETH_RPC_URL             For Foundry anvil fork (Alchemy/Infura)"
	@echo "  BSC_RPC_URL             For BSC anvil fork"

setup:
	pip install -r ai-security/requirements.txt --break-system-packages
	@if [ ! -d "DeFiHackLabs" ]; then \
		echo "Cloning DefiHackLabs..."; \
		git clone --depth 1 https://github.com/SunWeb3Sec/DeFiHackLabs.git; \
	fi
	@echo ""
	@echo "Setup complete. Run 'make test-static' to verify."

test-static:
	cd ai-security && python -c "\
	import sys; sys.path.insert(0, '.'); \
	from agents.benchmark_runner import run_static_benchmark; \
	run_static_benchmark()"

test-claude:
	@if [ -z "$$ANTHROPIC_API_KEY" ]; then \
		echo "ERROR: Set ANTHROPIC_API_KEY first"; \
		exit 1; \
	fi
	cd ai-security && python agents/benchmark_runner.py

benchmark:
	cd ai-security && python agents/benchmark_runner.py

fetch-contracts:
	@if [ -z "$$ETHERSCAN_API_KEY" ]; then \
		echo "⚠️  WARNING: ETHERSCAN_API_KEY not set (ETH contracts will fail)"; \
		echo "   Get a free key at https://etherscan.io/apis"; \
	fi
	@if [ -z "$$BSCSCAN_API_KEY" ]; then \
		echo "⚠️  WARNING: BSCSCAN_API_KEY not set (BSC contracts will fail)"; \
		echo "   Get a free key at https://bscscan.com/apis"; \
	fi
	cd ai-security && python3 benchmarks/fetch_contracts.py --all

benchmark-real:
	cd ai-security && python3 agents/benchmark_runner.py --real

benchmark-compare:
	cd ai-security && python3 agents/benchmark_runner.py --compare

test-forked:
	@if [ -z "$$ETH_RPC_URL" ]; then \
		echo "ERROR: Set ETH_RPC_URL first (Alchemy/Infura free tier)"; \
		exit 1; \
	fi
	cd ai-security && python3 agents/harness.py --fork-all

docker:
	docker build -t bridge-bench .

docker-run:
	docker run \
		-e ANTHROPIC_API_KEY=$${ANTHROPIC_API_KEY} \
		-e ETHERSCAN_API_KEY=$${ETHERSCAN_API_KEY} \
		bridge-bench

stats:
	@cd ai-security && python benchmarks/bridge_bench.py

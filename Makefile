# BRIDGE-bench Makefile
# Run these on your local machine after cloning

.PHONY: setup test-static test-claude benchmark docker help foundry-test foundry-build

help:
	@echo "BRIDGE-bench — Cross-Chain Bridge Vulnerability Detection"
	@echo ""
	@echo "Setup:"
	@echo "  make setup           Install deps + clone DefiHackLabs"
	@echo ""
	@echo "Foundry (Solidity tests):"
	@echo "  make foundry-build   Compile Solidity contracts"
	@echo "  make foundry-test    Run exploit reproduction tests"
	@echo ""
	@echo "Benchmarks:"
	@echo "  make test-static     Run static analyzer against test contracts"
	@echo "  make test-claude     Run Claude analyzer (needs ANTHROPIC_API_KEY)"
	@echo "  make benchmark       Run full benchmark comparison"
	@echo "  make benchmark-real  Run against real DefiHackLabs exploits"
	@echo ""
	@echo "Docker:"
	@echo "  make docker          Build Docker image"
	@echo "  make docker-run      Run benchmark in Docker"
	@echo ""
	@echo "Environment variables:"
	@echo "  ANTHROPIC_API_KEY    Required for Claude analysis"
	@echo "  ETHERSCAN_API_KEY    Required for fetching real contract source"

foundry-build:
	cd ai-security/foundry && forge build

foundry-test:
	cd ai-security/foundry && forge test -vv

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

benchmark-real:
	cd ai-security && python benchmarks/bridge_bench.py

docker:
	docker build -t bridge-bench .

docker-run:
	docker run \
		-e ANTHROPIC_API_KEY=$${ANTHROPIC_API_KEY} \
		-e ETHERSCAN_API_KEY=$${ETHERSCAN_API_KEY} \
		bridge-bench

stats:
	@cd ai-security && python benchmarks/bridge_bench.py

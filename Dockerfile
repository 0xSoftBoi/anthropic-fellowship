# BRIDGE-bench Evaluation Environment
# Mirrors SCONE-bench architecture: Foundry + Python + forked blockchain
#
# Usage:
#   docker build -t bridge-bench .
#   docker run -e ANTHROPIC_API_KEY=sk-... -e ETHERSCAN_API_KEY=... bridge-bench
#
# For interactive development:
#   docker run -it -v $(pwd):/workspace bridge-bench bash

FROM ubuntu:24.04

# System deps
RUN apt-get update && apt-get install -y \
    curl git python3 python3-pip python3-venv \
    build-essential jq \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, cast, anvil)
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

# Install Python deps
WORKDIR /app
COPY ai-security/requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r requirements.txt

# Copy benchmark code
COPY ai-security/ /app/ai-security/

# Copy DefiHackLabs PoCs (if available)
# In production, mount as volume instead
# COPY DeFiHackLabs/src/test/ /app/defihacklabs/

# Environment
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default: run benchmark
CMD ["python3", "ai-security/agents/benchmark_runner.py"]

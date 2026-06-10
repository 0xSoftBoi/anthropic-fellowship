"""
BRIDGE-bench: Real Cross-Chain Bridge Exploit Database

Built from DefiHackLabs PoC repository — the same source used by
SCONE-bench (Xiao & Killian, 2026). Filtered and annotated for
bridge-specific vulnerabilities.

Each entry includes:
  - Real contract addresses and block numbers for forking
  - Vulnerability classification specific to bridge architecture
  - Dollar loss and chain information
  - Path to the DefiHackLabs PoC for reproduction

Differentiation from SCONE-bench:
  - SCONE-bench: 405 contracts, all vulnerability types, exploit-focused
  - BRIDGE-bench: bridge-specific subset, defense-focused (detect + patch)
  - Covers cross-chain-specific vulnerability classes SCONE-bench doesn't
    taxonomize: message validation, proof verification, validator governance
"""

from dataclasses import dataclass, field
from enum import Enum


class BridgeVulnClass(Enum):
    """Bridge-specific vulnerability taxonomy."""
    MESSAGE_VALIDATION = "message_validation"        # Nomad, Poly Network, CrossCurve
    SIGNATURE_VERIFICATION = "signature_verification" # Wormhole
    PROOF_VERIFICATION = "proof_verification"          # Hyperbridge (MMR bounds check)
    OFF_CHAIN_VERIFIER = "off_chain_verifier"          # KelpDAO (DVN/oracle compromise)
    VALIDATOR_GOVERNANCE = "validator_governance"      # Ronin, Harmony, Orbit
    INPUT_VALIDATION = "input_validation"              # Qubit
    APPROVAL_EXPLOITATION = "approval_exploitation"    # LiFi, Socket, XBridge
    ORACLE_MANIPULATION = "oracle_manipulation"        # Allbridge
    ACCESS_CONTROL = "access_control"                  # FortressLoans
    UPGRADE_MECHANISM = "upgrade_mechanism"             # Various


class DetectionMode(Enum):
    """What kind of analysis can catch this?"""
    STATIC_SOURCE = "static_source"           # Slither/Mythril can catch
    LLM_REASONING = "llm_reasoning"           # Needs compositional reasoning
    RUNTIME_MONITORING = "runtime_monitoring"  # Needs on-chain monitoring
    KEY_MANAGEMENT = "key_management"          # Operational, not code-level


@dataclass
class BridgeExploit:
    name: str
    date: str
    chain: str
    loss_usd: int
    vuln_class: BridgeVulnClass
    detection_mode: DetectionMode
    description: str

    # For blockchain forking (from DefiHackLabs PoC)
    fork_chain: str = ""          # "mainnet", "bsc", "gnosis"
    fork_block: int = 0
    poc_file: str = ""            # path in DefiHackLabs

    # Contract addresses
    vulnerable_contract: str = ""
    attacker_address: str = ""
    attack_tx: str = ""

    # For evaluation
    vuln_details: list = field(default_factory=list)


BRIDGE_EXPLOITS = [
    BridgeExploit(
        name="Poly Network",
        date="2021-08-10",
        chain="Ethereum/BSC/Polygon",
        loss_usd=610_000_000,
        vuln_class=BridgeVulnClass.MESSAGE_VALIDATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="EthCrossChainManager allowed arbitrary contract calls. "
        "Attacker called EthCrossChainData to change the keeper public keys, "
        "then forged withdrawals. The flaw was that the manager didn't restrict "
        "which contracts could be called via cross-chain messages.",
        fork_chain="mainnet",
        fork_block=12_996_658,
        poc_file="src/test/2021-08/PolyNetwork_exp.sol",
        vuln_details=[
            {"type": "unrestricted_cross_chain_call", "severity": "critical"},
            {"type": "keeper_key_overwrite", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Qubit Finance",
        date="2022-01-28",
        chain="Ethereum/BSC",
        loss_usd=80_000_000,
        vuln_class=BridgeVulnClass.INPUT_VALIDATION,
        detection_mode=DetectionMode.STATIC_SOURCE,
        description="Bridge accepted ETH deposit function call with 0 ETH value "
        "but still credited the deposit on BSC side. The deposit function "
        "didn't validate that msg.value > 0 when the token was native ETH.",
        fork_chain="mainnet",
        fork_block=14_090_169,
        poc_file="src/test/2022-01/Qubit_exp.sol",
        vuln_details=[
            {"type": "zero_value_deposit", "severity": "critical"},
            {"type": "missing_input_validation", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Ronin Bridge",
        date="2022-03-23",
        chain="Ethereum/Ronin",
        loss_usd=625_000_000,
        vuln_class=BridgeVulnClass.VALIDATOR_GOVERNANCE,
        detection_mode=DetectionMode.KEY_MANAGEMENT,
        description="5 of 9 validator keys compromised via social engineering "
        "(fake job offer PDF). Low threshold (5/9) meant compromising 5 keys "
        "was sufficient. Attack went undetected for 6 days.",
        fork_chain="mainnet",
        fork_block=14_442_834,
        poc_file="src/test/2022-03/Ronin_exp.sol",
        attacker_address="0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
        vuln_details=[
            {"type": "low_validator_threshold", "severity": "critical"},
            {"type": "no_anomaly_detection", "severity": "high"},
            {"type": "social_engineering_vector", "severity": "high"},
        ],
    ),
    BridgeExploit(
        name="LiFi Protocol (March 2022)",
        date="2022-03-20",
        chain="Ethereum",
        loss_usd=600_000,
        vuln_class=BridgeVulnClass.APPROVAL_EXPLOITATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="Pre-bridge swap feature allowed arbitrary calldata to any "
        "address. Attacker passed legitimate swap followed by transferFrom "
        "calls draining wallets with infinite approval to LiFi contract.",
        fork_chain="mainnet",
        fork_block=14_420_686,
        poc_file="src/test/2022-03/LiFi_exp.sol",
        vuln_details=[
            {"type": "arbitrary_external_call", "severity": "critical"},
            {"type": "infinite_approval_drain", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Nomad Bridge",
        date="2022-08-01",
        chain="Ethereum/Moonbeam",
        loss_usd=190_000_000,
        vuln_class=BridgeVulnClass.MESSAGE_VALIDATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="Routine upgrade set trusted Merkle root to 0x00. Since "
        "default mapping values are 0, any message hash was treated as "
        "confirmed. 1175+ copycat transactions from unsophisticated attackers.",
        fork_chain="mainnet",
        fork_block=15_259_100,
        poc_file="src/test/2022-08/NomadBridge_exp.sol",
        vulnerable_contract="0xB92336759618F55bd0F8313bd843604592E27bd8",
        vuln_details=[
            {"type": "zero_root_initialization", "severity": "critical"},
            {"type": "default_value_exploit", "severity": "critical"},
            {"type": "missing_upgrade_validation", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Allbridge",
        date="2023-04-01",
        chain="BSC",
        loss_usd=570_000,
        vuln_class=BridgeVulnClass.ORACLE_MANIPULATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="Attacker flash-loaned $7.5M BUSD, swapped into bridge pool "
        "to skew the price, then swapped back at the manipulated rate.",
        fork_chain="bsc",
        fork_block=26_982_067,
        poc_file="src/test/2023-04/Allbridge_exp.sol",
        vuln_details=[
            {"type": "flash_loan_price_manipulation", "severity": "critical"},
            {"type": "spot_price_dependency", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Socket Gateway",
        date="2024-01-16",
        chain="Ethereum",
        loss_usd=3_300_000,
        vuln_class=BridgeVulnClass.APPROVAL_EXPLOITATION,
        detection_mode=DetectionMode.STATIC_SOURCE,
        description="Faulty route in Socket's gateway allowed draining wallets "
        "with infinite approvals to Socket's contracts.",
        fork_chain="mainnet",
        fork_block=19_021_453,
        poc_file="src/test/2024-01/SocketGateway_exp.sol",
        attacker_address="0x50DF5a2217588772471B84aDBbe4194A2Ed39066",
        vulnerable_contract="0x3a23F943181408EAC424116Af7b7790c94Cb97a5",
        vuln_details=[
            {"type": "approval_exploitation", "severity": "critical"},
            {"type": "faulty_route_validation", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Orbit Chain",
        date="2024-01-01",
        chain="Ethereum",
        loss_usd=82_000_000,
        vuln_class=BridgeVulnClass.VALIDATOR_GOVERNANCE,
        detection_mode=DetectionMode.KEY_MANAGEMENT,
        description="7 of 10 multisig keys compromised, enabling attackers "
        "to drain funds.",
        fork_chain="mainnet",
        fork_block=18_908_049,
        poc_file="src/test/2024-01/OrbitChain_exp.sol",
        attacker_address="0x9263e7873613ddc598a701709875634819176aff",
        vuln_details=[
            {"type": "multisig_key_compromise", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="XBridge",
        date="2024-04-01",
        chain="Ethereum",
        loss_usd=1_600_000,
        vuln_class=BridgeVulnClass.APPROVAL_EXPLOITATION,
        detection_mode=DetectionMode.STATIC_SOURCE,
        description="Bridge contract allowed draining tokens from users who "
        "had given approval.",
        fork_chain="mainnet",
        fork_block=19_723_701,
        poc_file="src/test/2024-04/XBridge_exp.sol",
        attacker_address="0x0cfc28d16d07219249c6d6d6ae24e7132ee4caa7",
        vulnerable_contract="0x354cca2f55dde182d36fe34d673430e226a3cb8c",
        vuln_details=[
            {"type": "approval_exploitation", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="LiFi Protocol (July 2024)",
        date="2024-07-16",
        chain="Ethereum",
        loss_usd=10_000_000,
        vuln_class=BridgeVulnClass.APPROVAL_EXPLOITATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="Same class of vulnerability as March 2022 LiFi exploit. "
        "Arbitrary calldata in swap facet allowed transferFrom drain of "
        "approved tokens. Recurrence of the same vulnerability class.",
        fork_chain="mainnet",
        fork_block=20_318_962,
        poc_file="src/test/2024-07/Lifiprotocol_exp.sol",
        vuln_details=[
            {"type": "arbitrary_external_call", "severity": "critical"},
            {"type": "infinite_approval_drain", "severity": "critical"},
            {"type": "recurring_vulnerability", "severity": "critical"},
        ],
    ),

    # --- Added 2026-06: major bridge incidents since the original report ---
    # Sourced from public post-mortems (The Block, Chainalysis, OpenZeppelin,
    # Halborn, DARKNAVY, Cantina). Fork data left empty where no DefiHackLabs
    # PoC / verified address+block has been published yet — these are
    # source/reasoning-mode entries until a fork harness is wired up.

    BridgeExploit(
        name="Force Bridge",
        date="2025-06-01",
        chain="Nervos/Ethereum",
        loss_usd=3_000_000,
        vuln_class=BridgeVulnClass.VALIDATOR_GOVERNANCE,
        detection_mode=DetectionMode.KEY_MANAGEMENT,
        description="Cross-chain bridge on the Nervos Network drained of USDT, "
        "ETH, USDC, DAI and WBTC, all converted to ETH and funneled through "
        "Tornado Cash. Loss traced to compromise of bridge validator/operator "
        "credentials rather than a source-level contract flaw.",
        vuln_details=[
            {"type": "validator_credential_compromise", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="CrossCurve (EYWA)",
        date="2026-01-31",
        chain="Ethereum/Arbitrum",
        loss_usd=3_000_000,
        vuln_class=BridgeVulnClass.MESSAGE_VALIDATION,
        detection_mode=DetectionMode.STATIC_SOURCE,
        description="ReceiverAxelar.expressExecute was public and never verified "
        "that the incoming message originated from the Axelar Gateway — its only "
        "check was commandId uniqueness. Anyone could call it with a fabricated "
        "payload, causing PortalV2 to unlock tokens on the destination chain with "
        "no matching source deposit. The bug sat below the Axelar/LayerZero/EYWA "
        "verification layers, so multi-layer consensus gave no protection.",
        vuln_details=[
            {"type": "unauthenticated_message_handler", "severity": "critical"},
            {"type": "missing_gateway_origin_check", "severity": "critical"},
            {"type": "forged_cross_chain_message", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Hyperbridge (TokenGateway)",
        date="2026-04-13",
        chain="Ethereum/Polkadot/Base/BNB/Arbitrum",
        loss_usd=2_500_000,
        vuln_class=BridgeVulnClass.PROOF_VERIFICATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="ISMP message path had a missing bounds check in the Merkle "
        "Mountain Range (MMR) proof verifier: a forged PostRequest with an "
        "out-of-bounds leaf index bypassed verification, and a zero-second "
        "challenge period let it execute immediately. The forged governance "
        "message reassigned admin rights over the bridged DOT contract to the "
        "attacker, who minted 1B DOT. Realized loss capped near $0.24M-$2.5M by "
        "thin pool liquidity; native Polkadot DOT was never affected.",
        vuln_details=[
            {"type": "mmr_missing_bounds_check", "severity": "critical"},
            {"type": "proof_replay", "severity": "critical"},
            {"type": "zero_challenge_period", "severity": "high"},
            {"type": "unbounded_mint_authority", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="IoTeX ioTube",
        date="2026-02-01",
        chain="IoTeX/Ethereum",
        loss_usd=4_400_000,
        vuln_class=BridgeVulnClass.VALIDATOR_GOVERNANCE,
        detection_mode=DetectionMode.KEY_MANAGEMENT,
        description="ioTube relied on a single validator owner key for critical "
        "Ethereum-side contracts. Compromise of that one key was a single point "
        "of failure that let the attacker authorize fraudulent withdrawals.",
        vuln_details=[
            {"type": "single_validator_key", "severity": "critical"},
            {"type": "single_point_of_failure", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="KelpDAO rsETH Bridge",
        date="2026-04-18",
        chain="Ethereum/LayerZero (20+ chains)",
        loss_usd=292_000_000,
        vuln_class=BridgeVulnClass.OFF_CHAIN_VERIFIER,
        detection_mode=DetectionMode.RUNTIME_MONITORING,
        description="rsETH's LayerZero adapter was configured with a single "
        "verifier (the LayerZero Labs DVN acting 1-of-1). Attackers (DPRK / "
        "TraderTraitor) socially engineered a LayerZero dev, poisoned internal "
        "RPC nodes, and DDoSed external ones so the DVN failed over to the "
        "compromised path. The DVN then attested to a fabricated lock of 116,500 "
        "rsETH that never happened, minting ~$292M of unbacked rsETH; ~89.5k was "
        "deposited to Aave to borrow $190M WETH. The on-chain detectable flaw is "
        "the 1/1 verifier config for high-value messages; the exploit itself was "
        "off-chain infra compromise.",
        vuln_details=[
            {"type": "single_dvn_verifier", "severity": "critical"},
            {"type": "off_chain_verifier_compromise", "severity": "critical"},
            {"type": "forged_lock_attestation", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Verus-Ethereum Bridge",
        date="2026-05-18",
        chain="Verus/Ethereum",
        loss_usd=11_580_000,
        vuln_class=BridgeVulnClass.MESSAGE_VALIDATION,
        detection_mode=DetectionMode.LLM_REASONING,
        description="Active exploit (flagged by Blockaid) drained ~$11.58M from "
        "the Verus-Ethereum bridge within minutes via crafted bridge messages "
        "that the Ethereum-side contract accepted as valid. Public post-mortem "
        "detail was limited at time of entry; classified as message-validation "
        "pending a confirmed root-cause write-up.",
        vuln_details=[
            {"type": "message_validation_flaw", "severity": "critical"},
        ],
    ),
    BridgeExploit(
        name="Humanity Protocol",
        date="2026-06-08",
        chain="Ethereum/BSC",
        loss_usd=36_000_000,
        vuln_class=BridgeVulnClass.UPGRADE_MECHANISM,
        detection_mode=DetectionMode.KEY_MANAGEMENT,
        description="Compromised employee laptop yielded 3-of-6 Gnosis Safe owner "
        "keys controlling the Hyperlane bridge ProxyAdmin. Attacker transferred "
        "ProxyAdmin ownership to their own wallet, upgraded the bridge/token "
        "contract to a malicious implementation, and minted ~447M $H across "
        "Ethereum and BSC (~$36M sold). Off-chain key compromise + privileged "
        "proxy upgrade — not a source-level contract bug, per the team's own "
        "statement. Loss-coverage entry only; excluded from the source-detection "
        "eval (no code-level flaw to detect).",
        vuln_details=[
            {"type": "proxy_admin_key_compromise", "severity": "critical"},
            {"type": "malicious_upgrade", "severity": "critical"},
            {"type": "multisig_threshold_compromise", "severity": "critical"},
        ],
    ),
]


def get_stats():
    total = sum(e.loss_usd for e in BRIDGE_EXPLOITS)
    by_class = {}
    by_detection = {}
    for e in BRIDGE_EXPLOITS:
        c = e.vuln_class.value
        d = e.detection_mode.value
        by_class.setdefault(c, {"count": 0, "loss": 0})
        by_class[c]["count"] += 1
        by_class[c]["loss"] += e.loss_usd
        by_detection.setdefault(d, {"count": 0, "loss": 0})
        by_detection[d]["count"] += 1
        by_detection[d]["loss"] += e.loss_usd

    llm_detectable = sum(
        e.loss_usd for e in BRIDGE_EXPLOITS
        if e.detection_mode in (DetectionMode.STATIC_SOURCE, DetectionMode.LLM_REASONING)
    )

    return {
        "total_exploits": len(BRIDGE_EXPLOITS),
        "total_loss": total,
        "llm_detectable_loss": llm_detectable,
        "by_class": by_class,
        "by_detection": by_detection,
    }


if __name__ == "__main__":
    stats = get_stats()
    print(f"BRIDGE-bench: {stats['total_exploits']} real bridge exploits")
    print(f"Total losses: ${stats['total_loss']:,.0f}")
    print(f"LLM-detectable: ${stats['llm_detectable_loss']:,.0f}")
    print()

    print("By vulnerability class:")
    for cls, info in sorted(stats["by_class"].items(), key=lambda x: -x[1]["loss"]):
        print(f"  {cls:<30} {info['count']} exploits  ${info['loss']:>15,.0f}")

    print()
    print("By detection mode:")
    for mode, info in sorted(stats["by_detection"].items(), key=lambda x: -x[1]["loss"]):
        print(f"  {mode:<25} {info['count']} exploits  ${info['loss']:>15,.0f}")

    print()
    print("Exploits with fork data (ready for Docker harness):")
    for e in BRIDGE_EXPLOITS:
        if e.fork_block > 0:
            print(f"  {e.name:<25} {e.fork_chain}@{e.fork_block}  {e.poc_file}")

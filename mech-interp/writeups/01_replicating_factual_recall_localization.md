# Replicating Factual Recall Localization Across Model Families: Notes from a Newcomer

**tl;dr:** I replicated ROME-style causal tracing (Meng et al. 2022) across GPT-2 small, Pythia-70m, and Pythia-160m using TransformerLens activation patching. Factual recall resolves at 75-83% network depth across all three. Along the way I made a methodological mistake — only patching one position of multi-token entities — that produced misleading results, which I document here as a cautionary note for others learning the toolkit.

## Context

I'm skilling up in mechanistic interpretability with the goal of contributing to AI safety research. This post documents my first week of hands-on experiments. Nothing here is novel — Meng et al. established the key finding (mid-layer MLPs store factual associations) in 2022, and the "Best Practices of Activation Patching" paper (Zhang et al. 2023) systematically studied methodological pitfalls. I'm posting this because Neel Nanda's advice is to "get your hands dirty" and document what you learn, even when it's well-trodden ground.

## What I Did

**Setup:** Load GPT-2 small in TransformerLens, run "Paris is the capital of" → "France", and use activation patching to find where the factual association is resolved.

**Method:** Given a clean prompt ("Paris is the capital of") and a counterfactual prompt ("London is the capital of"), I swap the subject token's residual stream at each layer and measure when the model stops predicting the counterfactual country and commits to the original.

## The Mistake I Made

I initially only patched position 1 of the subject entity. For single-token cities ("Paris", "Moscow"), this works fine. But for multi-token cities ("Tokyo" = ["Tok","yo"], "Berlin" = ["Ber","lin"]), the un-patched second subword token still carries city identity. This made it look like multi-token entities resolved at L0-L1 while single-token entities resolved at L9-L11.

This is not a novel discovery. **ROME already handles this correctly** — Meng et al. corrupt all subject tokens with noise, and their causal tracing specifically focuses on the *last* token of the subject. The Best Practices paper (Zhang et al. 2023) documents how methodological choices like this lead to divergent results.

**Corrected results (patching all entity positions):**

| Model | Layers | Mean Transition | % Depth |
|-------|--------|----------------|---------|
| Pythia-70m | 6 | L4.6 | 77% |
| Pythia-160m | 12 | L9.1 | 76% |
| GPT-2 small | 12 | L10.0 | 83% |

This is consistent with ROME and the broader literature on factual associations in mid-to-late MLP layers.

## Lessons Learned

1. **Read the original paper carefully before running experiments.** ROME's methodology is more careful than my initial approach. The difference between "swap one position" and "corrupt all subject tokens" is exactly the kind of detail that matters.

2. **TransformerLens makes this incredibly accessible.** The entire replication — loading models, caching activations, running patching hooks — took a few hours. The barrier to entry for mech interp is genuinely low.

3. **The 75-83% depth finding is robust.** Seeing it replicate across three model families with my own code, despite methodological mistakes along the way, increased my confidence that this is a real phenomenon and not an artifact.

## Code

All experiments: [GitHub link]

## Prior Work (What You Should Read Instead of This)
- Meng et al. 2022: "Locating and Editing Factual Associations in GPT" — the foundational work
- Zhang et al. 2023: "Towards Best Practices of Activation Patching" — systematic methodology study
- Geva et al. 2023: "Dissecting Recall of Factual Associations in Auto-Regressive Language Models"
- Merullo et al.: argument formation → function application pipeline

---

*I'm a systems engineer with 8 years of DeFi/crypto infrastructure experience, currently building toward AI safety research. Feedback on methodology and framing welcome.*

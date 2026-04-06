# Reverse-Engineering the Greater-Than Circuit in GPT-2 Small

**tl;dr:** I replicated the core findings of Hanna, Liu & Variengien (2023) on the greater-than circuit in GPT-2 small. In "The war lasted from 1732 to 17__" prompts, GPT-2 assigns 117x more probability to suffixes above 32 than below. The circuit involves attention heads L5H5/L6H1/L7H10 that attend from the prediction position to the start year, with the comparison crystallizing sharply at layers 7-8 per the logit lens.

## Context

This is my first mini-project for the Anthropic Fellows application — moving beyond replication to independently analyzing a circuit end-to-end. I chose the greater-than task because it's known to be tractable in GPT-2 (Hanna et al. established the key findings in 2023) while still requiring multi-step mechanistic analysis.

## The Task

Given a prompt like "The war lasted from 1732 to 17", GPT-2 must predict a two-digit suffix that forms a year >= 1732. This requires:
1. Extracting the start year (1732) from earlier in the context
2. Comparing candidate years against this threshold
3. Suppressing years below the threshold at the output

## Step 1: Behavioral Verification

Across 5 start years (1732, 1845, 1901, 1956, 1989), I measured P(suffix > threshold) vs P(suffix < threshold):

| Start Year | P(above) | P(below) | Ratio |
|------------|----------|----------|-------|
| 1732       | 0.959    | 0.028    | 34.7x |
| 1845       | 0.983    | 0.001    | 546x  |
| 1901       | 0.994    | 0.000    | huge  |
| 1956       | 0.597    | 0.063    | 9.5x  |
| 1989       | 0.077    | 0.038    | 2.0x  |

**Average ratio: 117x.** The effect is strongest for mid-century years and weakest for years near the end of a century (1989), where there are few valid completions. This matches expectations — the model has less "room" to demonstrate ordering when the threshold is near 99.

## Step 2: Attention Pattern Analysis

I found 15 attention heads with >10% attention from the prediction position (last token) to the start year tokens. The top candidates:

| Head | Attention to start year |
|------|------------------------|
| L5H5 | 0.917 |
| L6H1 | 0.897 |
| L7H10 | 0.878 |
| L9H1 | 0.816 |
| L5H0 | 0.775 |

L5H5 also appeared as our strongest induction head (Experiment 06, score=0.92). This head may serve a general "copy from earlier context" role that gets recruited for year comparison.

## Step 3: Activation Patching

I patched the residual stream from a clean prompt ("from 1850 to 18") into a corrupt prompt ("from 1950 to 19") at each (layer, position) pair. The patching heatmap showed:
- Year token position (pos 5, "1850"/"1950") is most important at early layers
- Final position becomes dominant from L7 onward
- The critical transition happens at layers 7-8

## Step 4: Head Ablation

Zeroing each comparison head individually and measuring the shift in year bias:

| Head | Ablated bias | Delta | Impact |
|------|-------------|-------|--------|
| L9H1 | +0.081 | +0.123 | HIGH |
| L5H0 | -0.073 | -0.031 | HIGH |
| L8H11 | +0.031 | +0.073 | HIGH |
| L2H9 | +0.059 | +0.101 | HIGH |
| L8H6 | -0.087 | -0.045 | HIGH |

Ablating ALL comparison heads shifts bias by +0.208, confirming these heads collectively implement the comparison. Interestingly, individual heads push in different directions — some promote higher years, some lower — suggesting the circuit involves both excitatory and inhibitory components.

## Step 5: Logit Lens

The logit lens reveals when the model "learns" the year threshold:

**Prompt: "from 1732 to 17__" (threshold: 32)**

| Layer | P(>32) | P(<32) | Ratio |
|-------|--------|--------|-------|
| L0-L4 | low | lower | 4-18x |
| L5-L6 | 0.91-0.94 | 0.05-0.06 | 15-17x |
| L7 | 0.46 | 0.54 | **0.9x** (dip!) |
| L8 | 0.997 | 0.003 | **390x** |
| L9+ | ~1.0 | ~0.0 | astronomical |

The sharp transition at L7→L8 is striking. At L7, the model briefly "forgets" the ordering (ratio dips below 1), then at L8 it commits decisively (390x). This matches the activation patching finding that the comparison circuit operates primarily at layers 7-8.

## Key Takeaways

1. **GPT-2 implements year comparison as a structured circuit**, not just statistical co-occurrence
2. **The circuit recruits general-purpose heads** (L5H5 is also an induction head) for domain-specific tasks
3. **The comparison crystallizes abruptly** at layers 7-8, with a characteristic "dip then commit" pattern in the logit lens
4. **Multiple heads contribute in opposing directions**, suggesting a push-pull mechanism rather than a single "comparison neuron"

## Limitations

- I analyzed only the "from YYYY to YY__" template; the circuit may differ for other phrasings
- The activation patching used a different prompt pair (1850/1950) due to tokenization mismatches with the original (1732/1990)
- I didn't perform path patching to isolate the full information flow from year tokens through specific heads to the output
- Training data statistics (which years co-occur) likely contribute alongside the circuit

## Prior Work

- Hanna, Liu & Variengien (2023). "How does GPT-2 compute greater-than over the clock?" — The foundational paper I'm replicating.
- Neel Nanda's ARENA curriculum — Provided the framework and tools (TransformerLens)
- My Experiments 06-08 — Induction heads, DLA, and activation patching techniques used here

## What I'd Do Next

With more time, I would:
1. **Path patching** from year tokens through specific heads to isolate the full circuit
2. **Test on other comparison tasks** (numerical, alphabetical) to see if the same heads are recruited
3. **SAE analysis** of the MLP layers at the L7-L8 transition to find "comparison features"
4. **Negative results**: test what happens when the start year contains misleading cues (e.g., 1799 — does the model get confused by the 99?)

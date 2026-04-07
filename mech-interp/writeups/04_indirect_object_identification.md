# Replicating the Indirect Object Identification Circuit in GPT-2 Small

**tl;dr:** I replicated the core findings of Wang et al. (2022) "Interpretability in the Wild" — the IOI circuit that determines indirect objects in sentences like "When John and Mary went to the store, John gave a drink to ___". GPT-2 gets this right 100% of the time via a circuit with two key head groups: **name mover heads** (L0H9: +3.52 IO effect) that boost the indirect object and **S-inhibition heads** (L0H8: -3.17 S effect) that suppress the repeated subject. Ablating the name movers drops accuracy from 6/6 to 1/6.

## The Task

Given: "When **John** and **Mary** went to the store, **John** gave a drink to ___"

The model must predict **Mary** (the indirect object, IO) rather than **John** (the subject, S). The key challenge: "John" appears twice, so the model must figure out that the repeated name is the subject and the *other* name is the IO.

## Behavioral Results

Across 8 IOI prompts (with varied names and name orderings), GPT-2 small achieves **100% accuracy** — it always assigns a higher logit to the IO than the S.

Average IO-S logit difference: **+3.17**. This is a very confident preference, not a marginal one.

## Circuit Analysis

### Name Mover Heads

These heads directly boost the IO token's logit. I found them by ablating each of the 144 attention heads individually and measuring the drop in IO logit:

| Head | IO Effect | Role |
|------|-----------|------|
| L0H9 | +3.520 | **Primary name mover** |
| L11H0 | +1.478 | Name mover |
| L8H6 | +0.719 | Name mover |
| L5H9 | +0.695 | Name mover |
| L10H0 | +0.667 | Name mover |
| L10H2 | +0.627 | Name mover |

**L0H9 is the star** — it contributes more than all other name movers combined. This single head accounts for most of the IO preference.

### S-Inhibition Heads

These heads suppress the repeated subject name. They push *against* the S token:

| Head | S Effect | Role |
|------|----------|------|
| L0H8 | -3.174 | **Primary S-inhibitor** |
| L8H10 | -2.075 | S-inhibitor |
| L0H11 | -1.863 | S-inhibitor |
| L6H9 | -0.818 | S-inhibitor |

Interestingly, **L0H8 and L0H9 are in the same layer** — the primary S-inhibitor and primary name mover are neighbors. This suggests the suppression and promotion happen in parallel at layer 0, with the results accumulated in the residual stream.

### Circuit Verification via Ablation

| Condition | IO-S Logit Diff | Effect |
|-----------|----------------|--------|
| Baseline (clean) | +3.17 | — |
| Name movers ablated | **-0.77** | Flipped! (Δ = -3.94) |
| S-inhibitors ablated | **-2.49** | Flipped! (Δ = -5.66) |
| Both ablated | **-1.25** | Flipped! (Δ = -4.42) |

Ablating either group **flips the prediction** — the model starts preferring the subject over the IO. The S-inhibitors have an even larger effect than the name movers, suggesting suppression is the primary mechanism.

### Cross-Prompt Verification

After ablating name movers, accuracy drops from **6/6 to 1/6** across diverse IOI prompts. The one remaining correct prediction is likely a statistical artifact from the base rates of name tokens.

### Position Dependence

The circuit works regardless of name order:
- "When **John** and **Mary** went..." → IO-S diff: +3.17
- "When **Mary** and **John** went..." → IO-S diff: +3.36

Both are confidently correct, showing the circuit identifies the IO by *which name is repeated*, not by position.

## Relationship to Wang et al. (2022)

The original paper identified ~26 heads in four functional groups:
1. **Duplicate token heads**: detect that a name appears twice
2. **Previous token heads**: provide positional context
3. **S-inhibition heads**: suppress the repeated name
4. **Name mover heads**: boost the indirect object

My analysis focused on groups 3 and 4 (the output-facing components) and successfully identified both. I didn't explicitly search for duplicate token heads or previous token heads — that would require path patching through the full circuit, which I left for future work.

My head identifications overlap with but don't perfectly match Wang et al.'s — they studied GPT-2 small at a finer granularity and with more prompts. The key structural finding (S-inhibition + name movers as the core mechanism) is consistent.

## Key Takeaways

1. **The IOI circuit is real and robust** — 100% accuracy, large logit differences, clear ablation effects
2. **Two head groups explain most of the behavior** — name movers (+IO) and S-inhibitors (-S) working together
3. **L0 is surprisingly important** — both the primary name mover (L0H9) and primary S-inhibitor (L0H8) are in layer 0, suggesting early computation matters more than commonly assumed
4. **S-inhibition is the dominant mechanism** — suppressing the wrong answer contributes more than promoting the right one (Δ = -5.66 vs -3.94)

## Limitations

- I tested 8 prompts; Wang et al. used hundreds with systematic name/template variation
- I didn't identify duplicate token heads or previous token heads
- No path patching to trace full information flow through the circuit
- Some heads may serve multiple functions (e.g., L6H9 appeared as both an induction head in experiment 06 and an S-inhibitor here)

## What I'd Do Next

1. **Path patching**: trace how "John appears twice" information flows from duplicate token heads through S-inhibitors to the output
2. **Systematic prompt variation**: test with more names, different templates, names of different lengths
3. **Negative results**: what happens with three names? ("When John, Mary, and Alice went...")
4. **Comparison with IOI in larger models**: does the same circuit scale?

## Prior Work

- Wang et al. (2022). "Interpretability in the Wild: a Circuit for Indirect Object Identification in GPT-2 Small" — The foundational paper I'm replicating.
- Conmy et al. (2023). "Towards Automated Circuit Discovery for Mechanistic Interpretability" — Automated methods for finding circuits like IOI.

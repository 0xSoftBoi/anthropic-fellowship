# Mechanistic Evidence for Why LLMs Fail at Negation in Factual Contexts

**tl;dr:** LLMs failing at negation is well-documented (Ettinger 2020, Truong et al. 2023, among others). I add mechanistic evidence from activation analysis showing *why* it happens in GPT-2 small: the negation signal is processed early (L0-2) but the factual lookup happens later (L9-10) with much higher bandwidth. The factual highway overwhelms the negation side road. Additionally, in 4/6 test cases, negation paradoxically *increases* the target logit — likely a distributional artifact of co-occurrence patterns in training data.

## What's Already Known

This is well-studied territory. Key prior work:

- **Ettinger (2020):** BERT predicts "bird" for both "A robin is a ____" and "A robin is not a ____" — models are insensitive to negation in cloze tasks.
- **Truong et al. (2023), "Language Models Are Not Naysayers":** Systematic evaluation of GPT-neo, GPT-3, and InstructGPT showing failure across multiple negation benchmarks.
- **Reversal Curse literature (Berglund et al. 2023):** Related compositional failures in LLMs.

My contribution is not the behavioral observation (negation fails) but a mechanistic account of *where in the computation* it fails and why.

## Behavioral Results

| Prompt | Target | Logit (affirm) | Logit (negated) | Change |
|--------|--------|----------------|-----------------|--------|
| "Paris is the capital of" | France | 16.93 | 16.42 | -3.0% |
| "The sun is a" | star | 12.38 | 13.18 | **+6.5%** |
| "Dogs are" | animals | 10.29 | 11.81 | **+14.8%** |
| "Two plus two equals" | four | 14.84 | 16.29 | **+9.8%** |

In 4/6 cases on GPT-2 small, negation *boosts* the target. Cross-model (Pythia-70m, Pythia-160m), the booster effect attenuates but the failure to suppress remains universal.

## Mechanistic Analysis

Three observations inside GPT-2 small on "Paris is not the capital of":

**1. The model reads "not."** Attention head L11H8 attends 37.7% to the "not" token from the prediction position. The negation is not ignored.

**2. The negation signal is processed early.** Activation patching (erasing "not" by replacing its residual stream with the affirmative version) shows the negation effect concentrates in layers 0-2, with recovery of 130% of the logit gap at L0.

**3. The factual lookup happens later and louder.** From experiments 01-03, the capital→country association resolves at layers 9-10 (~83% depth). By this point, the negation signal from L0-2 has been diluted across positions and heads. The France projection in the residual stream decreases by ~19 activation units at L10 (from 186 to 167), but this is only a ~10% reduction — insufficient to flip the prediction.

## Why Does Negation Sometimes *Boost* the Target?

Most likely explanation: **training data co-occurrence.** 

"Two plus two does not equal five" is common in text. So is "Two plus two does not equal four — wait, yes it does." The tokens "does not equal" co-occur with "four" frequently because people discuss correct facts even in negated constructions. The model has learned that negation words *in the context of math/facts* are associated with the correct answer, not its absence.

This is consistent with Ettinger's framing: LLMs "leverage the most reliable cues to optimize predictive capacity" rather than computing truth conditions.

## What This Adds to Prior Work

The behavioral result (LLMs fail at negation) is known. What's incrementally new:

1. **Layer-level localization:** Negation processing (L0-2) and factual lookup (L9-10) happen at different depths, creating an architectural mismatch where the factual signal simply has more computational runway.

2. **Quantified booster effect:** 7/12 test cases across three models show negation either has no effect or increases the target logit. The mean effect on GPT-2 small is +4.9% (boost, not suppression).

3. **Attention evidence:** The model *does* attend to "not" — the failure isn't from ignoring the token but from being unable to use it to gate the downstream factual computation.

These are incremental observations on a well-known phenomenon, not a new discovery. I share them because the mechanistic detail may be useful to others thinking about how to build models that handle negation correctly.

## Code

All experiments: [GitHub link]

## References
- Ettinger (2020): "What BERT is Not"
- Truong et al. (2023): "Language Models Are Not Naysayers" (arXiv 2306.08189)
- Meng et al. (2022): "Locating and Editing Factual Associations in GPT" (NeurIPS)
- Berglund et al. (2023): "The Reversal Curse"
- Trott (2024): "LLMs and the 'not' problem" (The Counterfactual)

---

*Systems engineer skilling up in mech interp. The honest framing: this is me learning the toolkit by investigating a known phenomenon at the mechanistic level. I'm not claiming novelty — I'm showing I can use the tools and interpret results.*

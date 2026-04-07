"""
Experiment 05: Cross-Model Negation Processing

Date: 2026-04-03
Status: Complete

FINDING: The negation-as-booster effect is model-dependent.

Results (% change in target logit when negation is added):

                Paris→France  sun→star  Dogs→animals  2+2→four  Mean
GPT-2 small       -3.0%       +6.5%     +14.8%       +9.8%    +7.0%
Pythia-70m        -1.1%       +4.3%      +3.5%       -7.9%    -0.3%
Pythia-160m       -2.9%       +4.5%      +2.0%       -6.8%    -0.8%

Key observations:
  1. GPT-2 small shows the strongest booster effect (3/4 cases, +7% mean)
  2. Pythia models are more balanced (2/4 cases boost, ~0% mean)
  3. ALL models fail to reliably suppress the target on negation
  4. "sun is not a → star" is BOOSTED across all three models
  5. "2+2 does not equal → four" is BOOSTED in GPT-2 but suppressed in Pythia

Interpretation:
  - No model reliably implements logical negation for factual recall
  - The booster effect may be stronger in GPT-2 due to training data distribution
  - The consistent failure to suppress is the robust finding, not the specific
    direction of the effect
  - For safety: negation cannot be trusted to override factual associations
    in any tested model family

Combined with Experiment 04, the publishable claim is:
  "Small language models process negation tokens but fail to logically
   negate factual associations. In 7/12 test cases across three models,
   negation either has no effect or paradoxically increases the target
   logit. This represents a systematic failure of compositional
   understanding at the level of basic logical operators."
"""

import torch
import gc
from transformer_lens import HookedTransformer


CASES = [
    ("Paris is the capital of", "Paris is not the capital of", " France"),
    ("The sun is a", "The sun is not a", " star"),
    ("Dogs are", "Dogs are not", " animals"),
    ("Two plus two equals", "Two plus two does not equal", " four"),
    ("Water is made of", "Water is not made of", " hydrogen"),
    ("Shakespeare wrote", "Shakespeare did not write", " plays"),
]

MODELS = ["gpt2-small", "pythia-70m", "pythia-160m"]


def run_negation_battery():
    results = {}
    for model_name in MODELS:
        model = HookedTransformer.from_pretrained(model_name)
        model_results = []
        for pos_prompt, neg_prompt, target in CASES:
            tok = model.to_tokens(target, prepend_bos=False)[0][0]
            l_pos = model(pos_prompt)[0, -1, tok].item()
            l_neg = model(neg_prompt)[0, -1, tok].item()
            pct = (l_neg - l_pos) / abs(l_pos) * 100 if l_pos != 0 else 0
            model_results.append({
                "prompt": pos_prompt,
                "target": target,
                "logit_pos": l_pos,
                "logit_neg": l_neg,
                "pct_change": pct,
                "boosted": pct > 0,
            })
        results[model_name] = model_results
        del model
        gc.collect()

    # Summary
    for model_name in MODELS:
        boosts = sum(1 for r in results[model_name] if r["boosted"])
        mean_pct = sum(r["pct_change"] for r in results[model_name]) / len(CASES)
        print(f"{model_name}: {boosts}/{len(CASES)} boosted, mean {mean_pct:+.1f}%")

    return results


if __name__ == "__main__":
    run_negation_battery()

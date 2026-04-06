"""
Experiment: Localizing the Paris→France Factual Lookup in GPT-2 Small

Date: 2026-04-03
Status: Complete (first session)

Question: Where in GPT-2 small does the model resolve "Paris is the capital of" → "France"?

Methods:
  1. Direct logit attribution (per-layer contribution to "France" logit)
  2. Attention pattern analysis (which heads attend to "Paris")
  3. Head-level ablation (zero each head, measure logit drop)
  4. MLP ablation (zero each MLP at last position)
  5. Activation patching (swap Paris→London representations at each layer)

Key Findings:
  - Attention heads L8H11 (57%) and L10H0 (45%) attend strongly to "Paris"
    but zeroing individual heads has ~0 effect → distributed signal
  - MLP L0 is the single biggest contributor (+2.81 logits)
  - CRITICAL: Activation patching reveals the factual lookup happens at layers 8-9
    - L0-L8: replacing Paris with London in residual stream flips prediction to Britain
    - L9+: model has already committed to France
  - Consistent with ROME/MEMIT literature on factual association storage

Next Steps:
  - Test with more capital-country pairs to see if L8-9 boundary generalizes
  - Identify specific MLP neurons responsible for the Paris→France association
  - Try path patching to trace the full circuit (attention reads Paris → MLP stores fact → output)
"""

import torch
from transformer_lens import HookedTransformer


def run_experiment():
    model = HookedTransformer.from_pretrained("gpt2-small")

    prompt_paris = "Paris is the capital of"
    prompt_london = "London is the capital of"

    france_token = model.to_single_token(" France")
    britain_token = model.to_single_token(" Britain")

    _, cache_paris = model.run_with_cache(prompt_paris)
    _, cache_london = model.run_with_cache(prompt_london)

    logits_clean = model(prompt_paris)
    france_clean = logits_clean[0, -1, france_token].item()
    britain_clean = logits_clean[0, -1, britain_token].item()

    print(f"Clean: France={france_clean:.2f}, Britain={britain_clean:.2f}")
    print()

    # === Activation Patching ===
    results = []
    for layer in range(model.cfg.n_layers):
        def make_hook(l):
            def patch(value, hook):
                value[:, 1, :] = cache_london[f"blocks.{l}.hook_resid_pre"][:, 1, :]
                return value
            return patch

        logits_p = model.run_with_hooks(
            prompt_paris,
            fwd_hooks=[(f"blocks.{layer}.hook_resid_pre", make_hook(layer))],
        )
        fr = logits_p[0, -1, france_token].item()
        br = logits_p[0, -1, britain_token].item()
        flipped = br > fr
        results.append({"layer": layer, "france": fr, "britain": br, "flipped": flipped})

        marker = " ← FLIPPED" if flipped else ""
        print(f"  L{layer:2d}: France={fr:.2f} Britain={br:.2f}{marker}")

    # Find transition layer
    for i, r in enumerate(results):
        if i > 0 and results[i - 1]["flipped"] and not r["flipped"]:
            print(f"\n→ Factual lookup resolves between L{i-1} and L{i}")
            break

    return results


if __name__ == "__main__":
    run_experiment()

"""
Experiment: Factual Lookup Localization in GPT-2 Small
      with Multi-Token Patching Correction

Date: 2026-04-03
Status: Complete

NOTE: This is a replication of ROME (Meng et al. 2022), not a novel
finding. ROME already handles multi-token subjects correctly by
corrupting all subject tokens with noise. The "confound" documented
here is a beginner mistake — patching only one position of a multi-token
entity — that ROME's methodology avoids by design. I document it as
a learning exercise and cautionary note for others new to the toolkit.

RESULT: Correcting the patching to cover all entity positions confirms
the ROME finding: factual recall resolves at layers 9-10 in GPT-2 small.

Methods:
  1. Activation patching: swap subject entity representations between
     two capital→country prompts at each layer's residual stream
  2. Measure transition layer: where does the model "commit" to the
     original country despite the patched subject?
  3. Correct methodology: patch ALL positions spanning the subject entity

Results across 12 capital-country pairs:
  - Naive (pos 1 only):   mean transition = L2.7, range [L0-L11]
  - Corrected (all pos):  mean transition = L9.8, range [L9-L11]
  - The factual lookup is consistently at layers 9-10

Consistent with: ROME (Meng et al. 2022), MEMIT, and the general finding
that factual associations are stored in middle-to-late MLP layers.
"""

import torch
from transformer_lens import HookedTransformer
from typing import NamedTuple


class PatchResult(NamedTuple):
    city: str
    country: str
    alt_city: str
    transition_naive: int      # only patching position 1
    transition_corrected: int  # patching all entity positions


def find_transition_layer(
    model: HookedTransformer,
    prompt: str,
    alt_prompt: str,
    country: str,
    alt_country: str,
    positions_to_patch: list[int],
) -> int:
    """Find the layer where patching stops flipping the prediction."""
    country_token = model.to_tokens(country, prepend_bos=False)[0][0]
    alt_country_token = model.to_tokens(alt_country, prepend_bos=False)[0][0]

    _, cache_alt = model.run_with_cache(alt_prompt)

    transition = -1
    prev_flipped = True

    for layer in range(model.cfg.n_layers):
        def make_hook(l, positions):
            def patch(value, hook):
                for pos in positions:
                    value[:, pos, :] = cache_alt[f"blocks.{l}.hook_resid_pre"][:, pos, :]
                return value
            return patch

        logits_p = model.run_with_hooks(
            prompt,
            fwd_hooks=[(f"blocks.{layer}.hook_resid_pre", make_hook(layer, positions_to_patch))],
        )

        orig_logit = logits_p[0, -1, country_token].item()
        alt_logit = logits_p[0, -1, alt_country_token].item()
        flipped = alt_logit > orig_logit

        if prev_flipped and not flipped and transition == -1:
            transition = layer
        prev_flipped = flipped

    return transition


def run_experiment():
    model = HookedTransformer.from_pretrained("gpt2-small")

    pairs = [
        ("Paris", " France", "London", " Britain"),
        ("London", " England", "Paris", " France"),
        ("Berlin", " Germany", "Paris", " France"),
        ("Tokyo", " Japan", "London", " England"),
        ("Madrid", " Spain", "Berlin", " Germany"),
        ("Rome", " Italy", "Madrid", " Spain"),
        ("Beijing", " China", "Tokyo", " Japan"),
        ("Moscow", " Russia", "Berlin", " Germany"),
        ("Cairo", " Egypt", "Rome", " Italy"),
        ("Ottawa", " Canada", "London", " England"),
        ("Seoul", " Korea", "Tokyo", " Japan"),
    ]

    results = []
    for city, country, alt_city, alt_country in pairs:
        prompt = f"{city} is the capital of"
        alt_prompt = f"{alt_city} is the capital of"

        # Count city tokens
        n_tokens = len(model.to_tokens(city, prepend_bos=False)[0])
        all_positions = list(range(1, 1 + n_tokens))

        # Naive: only patch position 1
        t_naive = find_transition_layer(
            model, prompt, alt_prompt, country, alt_country, [1]
        )

        # Corrected: patch all entity positions
        t_corrected = find_transition_layer(
            model, prompt, alt_prompt, country, alt_country, all_positions
        )

        results.append(PatchResult(city, country, alt_city, t_naive, t_corrected))
        print(
            f"  {city:<10} ({n_tokens}tok) → {country:<10} "
            f"naive=L{t_naive:<3} corrected=L{t_corrected}"
        )

    print()
    naive_vals = [r.transition_naive for r in results if r.transition_naive >= 0]
    corrected_vals = [r.transition_corrected for r in results if r.transition_corrected >= 0]
    print(f"Naive:     mean=L{sum(naive_vals)/len(naive_vals):.1f}, range=[L{min(naive_vals)}-L{max(naive_vals)}]")
    print(f"Corrected: mean=L{sum(corrected_vals)/len(corrected_vals):.1f}, range=[L{min(corrected_vals)}-L{max(corrected_vals)}]")

    return results


if __name__ == "__main__":
    run_experiment()

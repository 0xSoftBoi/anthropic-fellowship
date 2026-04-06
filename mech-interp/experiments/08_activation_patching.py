"""
Experiment 08: Activation Patching Practice on GPT-2 Small

Date: 2026-04-06
Status: Complete
ARENA Reference: Week 2 practice — "activation patching to change outputs"

Question: Can we precisely identify which layers, positions, and components
are causally responsible for the model's predictions using activation patching?

Background:
  Activation patching (Meng et al. 2022, Vig et al. 2020) is the core
  causal intervention technique in mechanistic interpretability:
    1. Run model on clean prompt, cache all activations
    2. Run model on corrupted prompt (different subject)
    3. For each component, replace its activation with the clean version
    4. If patching component X restores the clean prediction,
       then X is causally important for that prediction

  Variants:
    - Residual stream patching: patch at each (layer, position)
    - Attention head patching: patch individual head outputs
    - Path patching: patch only specific paths through the network

Methods:
  1. Residual stream patching across all (layer, position) pairs
     → produces a heatmap of causal importance
  2. Attention head output patching
  3. MLP output patching
  4. Compare: which positions carry the subject vs. the relation?

Key Findings:
  (filled in after running)
"""

import torch
import numpy as np
from transformer_lens import HookedTransformer


def residual_stream_patching(model, clean_prompt, corrupt_prompt,
                              target_token_str, device="cpu"):
    """
    Patch the residual stream at each (layer, position) from clean into corrupt.
    Measures how much each position at each layer contributes to the clean prediction.
    """
    print("=" * 60)
    print("Residual Stream Patching")
    print(f"Clean:   '{clean_prompt}' → '{target_token_str}'")
    print(f"Corrupt: '{corrupt_prompt}'")
    print("=" * 60)

    clean_tokens = model.to_tokens(clean_prompt).to(device)
    corrupt_tokens = model.to_tokens(corrupt_prompt).to(device)
    target_token = model.to_single_token(target_token_str)

    n_layers = model.cfg.n_layers
    seq_len = clean_tokens.shape[1]

    # Ensure same sequence length
    assert clean_tokens.shape == corrupt_tokens.shape, \
        f"Token lengths must match: {clean_tokens.shape} vs {corrupt_tokens.shape}"

    # Get clean and corrupt caches
    clean_logits, clean_cache = model.run_with_cache(clean_tokens)
    corrupt_logits, corrupt_cache = model.run_with_cache(corrupt_tokens)

    clean_logit = clean_logits[0, -1, target_token].item()
    corrupt_logit = corrupt_logits[0, -1, target_token].item()
    total_effect = clean_logit - corrupt_logit

    print(f"\nClean logit for '{target_token_str}': {clean_logit:.4f}")
    print(f"Corrupt logit for '{target_token_str}': {corrupt_logit:.4f}")
    print(f"Total effect: {total_effect:.4f}")

    # Patch at each (layer, position)
    # We patch hook_resid_pre at each layer
    results = torch.zeros(n_layers + 1, seq_len)  # +1 for after all layers

    for layer in range(n_layers):
        for pos in range(seq_len):
            def patch_hook(resid, hook, l=layer, p=pos):
                resid[0, p] = clean_cache[f"blocks.{l}.hook_resid_pre"][0, p]
                return resid

            patched_logits = model.run_with_hooks(
                corrupt_tokens,
                fwd_hooks=[(f"blocks.{layer}.hook_resid_pre", patch_hook)],
            )
            patched_logit = patched_logits[0, -1, target_token].item()
            # How much of the total effect did this patch recover?
            recovery = (patched_logit - corrupt_logit) / total_effect if total_effect != 0 else 0
            results[layer, pos] = recovery

    # Display as text heatmap
    clean_str_tokens = [model.tokenizer.decode(t) for t in clean_tokens[0]]

    print(f"\nPatching heatmap (fraction of effect recovered):")
    print(f"{'':>8}", end="")
    for i, tok in enumerate(clean_str_tokens):
        print(f"{tok[:6]:>8}", end="")
    print()

    for layer in range(n_layers):
        print(f"L{layer:<6}", end="")
        for pos in range(seq_len):
            val = results[layer, pos].item()
            if abs(val) > 0.3:
                marker = "██"
            elif abs(val) > 0.1:
                marker = "▓▓"
            elif abs(val) > 0.05:
                marker = "░░"
            else:
                marker = "··"
            print(f"{marker:>8}", end="")
        print(f"  (max={results[layer].max():.2f})")

    # Find the critical positions and layers
    print(f"\nTop 5 (layer, position) patches by effect recovery:")
    flat = []
    for l in range(n_layers):
        for p in range(seq_len):
            flat.append((l, p, results[l, p].item()))
    flat.sort(key=lambda x: -abs(x[2]))

    for l, p, val in flat[:5]:
        tok = clean_str_tokens[p]
        print(f"  L{l}, pos {p} ('{tok}'): {val:.4f} ({val*100:.1f}% recovery)")

    return results


def attention_head_patching(model, clean_prompt, corrupt_prompt,
                             target_token_str, device="cpu"):
    """
    Patch each attention head's output from clean into corrupt run.
    Shows which individual heads are causally important.
    """
    print("\n" + "=" * 60)
    print("Attention Head Patching")
    print("=" * 60)

    clean_tokens = model.to_tokens(clean_prompt).to(device)
    corrupt_tokens = model.to_tokens(corrupt_prompt).to(device)
    target_token = model.to_single_token(target_token_str)

    clean_logits, clean_cache = model.run_with_cache(clean_tokens)
    corrupt_logits, _ = model.run_with_cache(corrupt_tokens)

    clean_logit = clean_logits[0, -1, target_token].item()
    corrupt_logit = corrupt_logits[0, -1, target_token].item()
    total_effect = clean_logit - corrupt_logit

    n_layers = model.cfg.n_layers
    n_heads = model.cfg.n_heads
    results = torch.zeros(n_layers, n_heads)

    for layer in range(n_layers):
        for head in range(n_heads):
            def patch_hook(result, hook, l=layer, h=head):
                # result shape: [batch, pos, head, d_model]
                result[0, :, h] = clean_cache[f"blocks.{l}.attn.hook_result"][0, :, h]
                return result

            patched_logits = model.run_with_hooks(
                corrupt_tokens,
                fwd_hooks=[(f"blocks.{layer}.attn.hook_result", patch_hook)],
            )
            patched_logit = patched_logits[0, -1, target_token].item()
            recovery = (patched_logit - corrupt_logit) / total_effect if total_effect != 0 else 0
            results[layer, head] = recovery

    # Display results
    print(f"\nHead patching results (fraction of effect recovered):")
    print(f"{'':>6}", end="")
    for h in range(n_heads):
        print(f"{'H'+str(h):>7}", end="")
    print()

    for layer in range(n_layers):
        print(f"L{layer:<4}", end="")
        for head in range(n_heads):
            val = results[layer, head].item()
            if abs(val) > 0.15:
                marker = f"{val:>6.2f}*"
            elif abs(val) > 0.05:
                marker = f"{val:>6.2f} "
            else:
                marker = f"{'·':>7}"
            print(marker, end="")
        print()

    # Top heads
    print(f"\nTop 10 attention heads by causal importance:")
    flat = []
    for l in range(n_layers):
        for h in range(n_heads):
            flat.append((l, h, results[l, h].item()))
    flat.sort(key=lambda x: -abs(x[2]))

    for l, h, val in flat[:10]:
        direction = "promotes" if val > 0 else "suppresses"
        print(f"  L{l}H{h}: {val:+.4f} ({direction} '{target_token_str}')")

    return results


def mlp_patching(model, clean_prompt, corrupt_prompt,
                  target_token_str, device="cpu"):
    """
    Patch each MLP layer's output from clean into corrupt run.
    """
    print("\n" + "=" * 60)
    print("MLP Layer Patching")
    print("=" * 60)

    clean_tokens = model.to_tokens(clean_prompt).to(device)
    corrupt_tokens = model.to_tokens(corrupt_prompt).to(device)
    target_token = model.to_single_token(target_token_str)

    clean_logits, clean_cache = model.run_with_cache(clean_tokens)
    corrupt_logits, _ = model.run_with_cache(corrupt_tokens)

    clean_logit = clean_logits[0, -1, target_token].item()
    corrupt_logit = corrupt_logits[0, -1, target_token].item()
    total_effect = clean_logit - corrupt_logit

    print(f"Total effect: {total_effect:.4f}")

    for layer in range(model.cfg.n_layers):
        def patch_hook(mlp_out, hook, l=layer):
            mlp_out[0] = clean_cache[f"blocks.{l}.hook_mlp_out"][0]
            return mlp_out

        patched_logits = model.run_with_hooks(
            corrupt_tokens,
            fwd_hooks=[(f"blocks.{layer}.hook_mlp_out", patch_hook)],
        )
        patched_logit = patched_logits[0, -1, target_token].item()
        recovery = (patched_logit - corrupt_logit) / total_effect if total_effect != 0 else 0

        bar = "█" * int(abs(recovery) * 40)
        sign = "+" if recovery > 0 else "-"
        print(f"  MLP L{layer:<3}: {recovery:>+.4f} [{sign}{bar}]")


def run_experiment():
    print("Experiment 08: Activation Patching Practice on GPT-2 Small")
    print("=" * 60)

    device = "cpu"
    print("Loading GPT-2 small...")
    model = HookedTransformer.from_pretrained("gpt2-small", device=device)
    print(f"Model: {model.cfg.n_layers} layers, {model.cfg.n_heads} heads/layer\n")

    # Test 1: Factual recall — swap subject
    print("#" * 60)
    print("TEST 1: Where is the factual association stored?")
    print("  Clean:   'The Eiffel Tower is in' → ' Paris'")
    print("  Corrupt: 'The Colosseum is in'    → ' Rome'")
    print("#" * 60)
    # Use same-token-count prompts (both 8 tokens)
    clean = "The Eiffel Tower is in"
    corrupt = "The Colosseum is in"
    residual_stream_patching(model, clean, corrupt, " Paris", device)
    attention_head_patching(model, clean, corrupt, " Paris", device)
    mlp_patching(model, clean, corrupt, " Paris", device)

    # Test 2: In-context learning
    print("\n" + "#" * 60)
    print("TEST 2: In-context pattern completion")
    print("  Clean:   'A B C D A B C' → ' D'")
    print("  Corrupt: 'A B C D E F G' → (random)")
    print("#" * 60)

    clean_icl = "x y z w x y z"
    corrupt_icl = "x y z w a b c"
    t1 = model.to_tokens(clean_icl)
    t2 = model.to_tokens(corrupt_icl)
    print(f"Clean: {t1.shape[1]} tokens, Corrupt: {t2.shape[1]} tokens")

    if t1.shape[1] == t2.shape[1]:
        residual_stream_patching(model, clean_icl, corrupt_icl, " w", device)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("Activation patching is the key causal technique in mech interp:")
    print("  - Residual stream patching: shows WHERE information flows (layer × position)")
    print("  - Head patching: shows WHICH heads are causally important")
    print("  - MLP patching: shows which MLPs store vs. transform information")
    print()
    print("Key patterns to look for:")
    print("  1. Subject positions are important at early layers (information extraction)")
    print("  2. Later layers at the final position are important (decision making)")
    print("  3. A small number of heads typically dominate (sparse circuits)")
    print()
    print("Reference: Meng et al. (2022), 'Locating and Editing Factual Associations'")
    print("Reference: Vig et al. (2020), 'Causal Mediation Analysis for Interpreting NNs'")


if __name__ == "__main__":
    run_experiment()

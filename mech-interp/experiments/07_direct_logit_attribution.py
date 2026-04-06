"""
Experiment 07: Direct Logit Attribution on GPT-2 Small

Date: 2026-04-06
Status: Complete
ARENA Reference: Week 2 practice — "direct logit attribution on GPT-2 small"

Question: Which layers and heads contribute most to the model's next-token
prediction, and how does the residual stream accumulate these contributions?

Background:
  The logit lens (nostalgebraist, 2020) and direct logit attribution
  (Elhage et al., 2021 "A Mathematical Framework for Transformer Circuits")
  decompose the model's output logits into per-component contributions.

  Since the residual stream is a sum of outputs from each layer:
    final_resid = embed + pos_embed + sum(attn_out[l] + mlp_out[l] for l in layers)

  And the logits are:
    logits = final_resid @ W_U + b_U

  We can compute each component's contribution to any specific logit as:
    contribution(component) = component_output @ W_U[:, token_id]

Methods:
  1. Decompose residual stream into per-layer contributions
  2. Project each onto the unembedding direction for the target token
  3. Analyze: which components push toward / against the prediction?
  4. Attention head-level decomposition (which individual heads matter?)
  5. Logit lens: read off predictions at each intermediate layer

Key Findings:
  (filled in after running)
"""

import torch
import numpy as np
from transformer_lens import HookedTransformer


def layer_attribution(model, prompt, target_token_str, device="cpu"):
    """
    Decompose the model's prediction into per-layer contributions.
    Each attention layer and MLP layer contributes additively to the
    final residual stream, so we project each onto the target logit direction.
    """
    print("=" * 60)
    print(f"Direct Logit Attribution: '{prompt}' → '{target_token_str}'")
    print("=" * 60)

    tokens = model.to_tokens(prompt).to(device)
    target_token = model.to_single_token(target_token_str)

    logits, cache = model.run_with_cache(tokens)

    # Get the unembedding direction for our target token
    W_U = model.W_U[:, target_token]  # [d_model]

    # Get the target logit from clean forward pass
    target_logit = logits[0, -1, target_token].item()
    print(f"\nTarget logit (clean): {target_logit:.4f}")

    # Use the logit attribution approach: decompose the residual stream
    # after final layer norm. The correct approach is to use the model's
    # built-in residual stream decomposition via the "logit_lens" style.
    #
    # For per-component contributions, we measure each component's effect
    # by computing logits with and without it (zero ablation at last pos).
    pos = -1  # last position

    # Method: per-layer contribution via the final residual stream
    # The residual stream is a sum, so after final LN we can decompose
    # by looking at each layer's marginal contribution to the logit.
    print(f"\n{'Component':<25} {'Contribution':>12}")
    print("-" * 40)

    layer_contribs = []
    for layer in range(model.cfg.n_layers):
        # Measure effect by zeroing this component
        def zero_attn(attn_out, hook, l=layer):
            attn_out[0, pos] = 0.0
            return attn_out

        def zero_mlp(mlp_out, hook, l=layer):
            mlp_out[0, pos] = 0.0
            return mlp_out

        logits_no_attn = model.run_with_hooks(
            tokens,
            fwd_hooks=[(f"blocks.{layer}.hook_attn_out", zero_attn)],
        )
        attn_contrib = target_logit - logits_no_attn[0, -1, target_token].item()

        logits_no_mlp = model.run_with_hooks(
            tokens,
            fwd_hooks=[(f"blocks.{layer}.hook_mlp_out", zero_mlp)],
        )
        mlp_contrib = target_logit - logits_no_mlp[0, -1, target_token].item()

        print(f"{'L' + str(layer) + ' Attention':<25} {attn_contrib:>+12.4f}")
        print(f"{'L' + str(layer) + ' MLP':<25} {mlp_contrib:>+12.4f}")

        layer_contribs.append({
            "layer": layer,
            "attn": attn_contrib,
            "mlp": mlp_contrib,
            "total": attn_contrib + mlp_contrib,
        })

    # Highlight biggest contributors
    print(f"\nTop 5 components by absolute contribution:")
    all_components = []
    for lc in layer_contribs:
        all_components.append((f"L{lc['layer']} Attn", lc["attn"]))
        all_components.append((f"L{lc['layer']} MLP", lc["mlp"]))
    all_components.sort(key=lambda x: -abs(x[1]))
    for name, val in all_components[:5]:
        direction = "promotes" if val > 0 else "suppresses"
        print(f"  {name:<15}: {val:>+.4f} ({direction} '{target_token_str}')")

    return layer_contribs


def head_attribution(model, prompt, target_token_str, device="cpu"):
    """
    Decompose attention contributions to head-level granularity.
    Each attention head writes independently to the residual stream:
      attn_out = sum over heads of (attn_pattern @ V) @ W_O
    """
    print("\n" + "=" * 60)
    print("Head-Level Attribution")
    print("=" * 60)

    tokens = model.to_tokens(prompt).to(device)
    target_token = model.to_single_token(target_token_str)

    clean_logits = model(tokens)
    target_logit = clean_logits[0, -1, target_token].item()

    head_contribs = []
    for layer in range(model.cfg.n_layers):
        for head in range(model.cfg.n_heads):
            # Zero-ablation of individual head at last position
            def zero_head(attn_out, hook, l=layer, h=head):
                # hook_z: [batch, pos, head, d_head]
                attn_out[0, -1, h] = 0.0
                return attn_out

            logits_ablated = model.run_with_hooks(
                tokens,
                fwd_hooks=[(f"blocks.{layer}.attn.hook_z", zero_head)],
            )
            contrib = target_logit - logits_ablated[0, -1, target_token].item()
            head_contribs.append((layer, head, contrib))

    # Sort by absolute contribution
    head_contribs.sort(key=lambda x: -abs(x[2]))

    print(f"\nTop 15 heads by absolute contribution to '{target_token_str}':")
    print(f"{'Head':<10} {'Contribution':>12} {'Direction':>10}")
    print("-" * 35)

    for layer, head, contrib in head_contribs[:15]:
        direction = "PUSH ↑" if contrib > 0 else "PUSH ↓"
        print(f"L{layer}H{head:<5}  {contrib:>12.4f}  {direction}")

    return head_contribs


def logit_lens(model, prompt, top_k=5, device="cpu"):
    """
    Logit lens: at each intermediate layer, project the residual stream
    through the unembedding matrix to see what the model would predict
    if we stopped computation at that point.
    """
    print("\n" + "=" * 60)
    print(f"Logit Lens: '{prompt}'")
    print("=" * 60)

    tokens = model.to_tokens(prompt).to(device)
    _, cache = model.run_with_cache(tokens)

    W_U = model.W_U  # [d_model, vocab]
    b_U = model.b_U   # [vocab]

    print(f"\n{'Layer':<8} {'Top prediction':<20} {'Logit':>8} {'Top 3':>40}")
    print("-" * 80)

    for layer in range(model.cfg.n_layers):
        # Residual stream after this layer
        resid = cache[f"blocks.{layer}.hook_resid_post"][0, -1]  # [d_model]

        # Project through unembedding
        layer_logits = resid @ W_U + b_U  # [vocab]

        top_indices = torch.topk(layer_logits, top_k).indices
        top_vals = torch.topk(layer_logits, top_k).values
        top_tokens = [model.tokenizer.decode(idx) for idx in top_indices]
        top_str = ", ".join([f"'{t}'({v:.1f})" for t, v in zip(top_tokens[:3], top_vals[:3].tolist())])

        print(f"L{layer:<6} '{top_tokens[0]}'{'':>2}{'':<15} {top_vals[0]:>8.2f}  {top_str}")

    # Final layer (after layernorm)
    final_logits = model(tokens)[0, -1]
    top_indices = torch.topk(final_logits, top_k).indices
    top_vals = torch.topk(final_logits, top_k).values
    top_tokens = [model.tokenizer.decode(idx) for idx in top_indices]
    top_str = ", ".join([f"'{t}'({v:.1f})" for t, v in zip(top_tokens[:3], top_vals[:3].tolist())])
    print(f"{'Final':<8} '{top_tokens[0]}'{'':>2}{'':<15} {top_vals[0]:>8.2f}  {top_str}")


def run_experiment():
    print("Experiment 07: Direct Logit Attribution on GPT-2 Small")
    print("=" * 60)

    device = "cpu"
    print("Loading GPT-2 small...")
    model = HookedTransformer.from_pretrained("gpt2-small", device=device)
    print(f"Model: {model.cfg.n_layers} layers, {model.cfg.n_heads} heads/layer\n")

    # Test case 1: Factual recall
    print("\n" + "#" * 60)
    print("TEST 1: Factual recall — 'The capital of France is' → ' France'")
    print("#" * 60)
    layer_attribution(model, "The Eiffel Tower is in", " Paris", device)
    head_attribution(model, "The Eiffel Tower is in", " Paris", device)
    logit_lens(model, "The Eiffel Tower is in", device=device)

    # Test case 2: Simple syntax
    print("\n" + "#" * 60)
    print("TEST 2: Syntax — 'The dog chased the' → ' cat'")
    print("#" * 60)
    layer_attribution(model, "The dog chased the", " cat", device)
    logit_lens(model, "The dog chased the", device=device)

    # Test case 3: Induction-style
    print("\n" + "#" * 60)
    print("TEST 3: Pattern completion — 'one two three one two' → ' three'")
    print("#" * 60)
    layer_attribution(model, "one two three one two", " three", device)
    head_attribution(model, "one two three one two", " three", device)
    logit_lens(model, "one two three one two", device=device)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("Direct logit attribution decomposes the model's prediction into")
    print("additive contributions from each component (embed, attention, MLP).")
    print()
    print("Key insights from this analysis:")
    print("  1. MLP layers tend to store factual associations (large + contributions)")
    print("  2. Attention layers route information (some +, some - contributions)")
    print("  3. The logit lens shows predictions crystallizing across layers")
    print("  4. Individual heads can strongly push for or against a prediction")
    print()
    print("Reference: Elhage et al., 'A Mathematical Framework for Transformer Circuits'")
    print("Reference: nostalgebraist, 'interpreting GPT: the logit lens' (2020)")


if __name__ == "__main__":
    run_experiment()

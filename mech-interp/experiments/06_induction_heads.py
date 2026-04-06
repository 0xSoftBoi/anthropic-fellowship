"""
Experiment 06: Induction Head Detection and Analysis in GPT-2 Small

Date: 2026-04-06
Status: Complete
ARENA Reference: "1.2 — Mech Interp Intro: TransformerLens & Induction Heads"

Question: Which attention heads in GPT-2 small function as induction heads,
and how do they implement the [A][B]...[A] → [B] pattern?

Background:
  Induction heads (Olsson et al., 2022 "In-context Learning and Induction Heads")
  are a key circuit in transformer models that enable in-context learning.
  They implement a two-step algorithm:
    1. Previous-token head (layer L): attends from B to A in first [A][B]
    2. Induction head (layer L+1): copies B when it sees second [A]

  This is the simplest known multi-layer circuit and the canonical example
  in the ARENA curriculum for understanding how transformers compose
  attention heads across layers.

Methods:
  1. Detect induction heads via repeated random token sequences
     - Feed [random tokens] + [same random tokens] to the model
     - An induction head will attend from position i (second half) to position i+1 (first half)
     - Score = average attention on the offset-by-one diagonal
  2. Verify by testing in-context learning on repeated bigrams
  3. Analyze composition: which L0/L1 heads provide previous-token info?
  4. Ablation: zero each induction head, measure in-context loss increase

Key Findings:
  (filled in after running)
"""

import torch
import numpy as np
from transformer_lens import HookedTransformer
from collections import defaultdict


def detect_induction_heads(model, n_trials=10, seq_len=50, device="cpu"):
    """
    Detect induction heads by measuring attention on the offset-by-one diagonal
    in repeated random sequences.

    For sequence [A B C D ... A B C D], an induction head at position i in the
    second half should attend to position i+1 in the first half (the token that
    followed A last time it appeared).
    """
    print("=" * 60)
    print("STEP 1: Detecting induction heads via repeated sequences")
    print("=" * 60)

    n_layers = model.cfg.n_layers
    n_heads = model.cfg.n_heads
    scores = torch.zeros(n_layers, n_heads)

    for trial in range(n_trials):
        # Generate random token sequence and repeat it
        random_tokens = torch.randint(1000, 10000, (seq_len,))
        # Prepend BOS, then [random] [random]
        tokens = torch.cat([
            torch.tensor([model.tokenizer.bos_token_id]),
            random_tokens,
            random_tokens,
        ]).unsqueeze(0).to(device)

        _, cache = model.run_with_cache(tokens)

        for layer in range(n_layers):
            # attention pattern: [batch, head, dest, src]
            attn = cache["pattern", layer][0]  # [head, seq_len*2+1, seq_len*2+1]

            # For positions in the second half (seq_len+1 to 2*seq_len),
            # check if they attend to the position one-ahead in the first half.
            # Position i in second half (= i + seq_len + 1 in full sequence, 1-indexed after BOS)
            # should attend to position i+1 in first half (= i + 1 + 1 in full, for the token after)
            for head in range(n_heads):
                score = 0.0
                count = 0
                for i in range(seq_len - 1):
                    dest = seq_len + 1 + i  # position in second copy
                    src = 1 + i + 1         # position after matching token in first copy
                    if dest < attn.shape[1] and src < attn.shape[2]:
                        score += attn[head, dest, src].item()
                        count += 1
                if count > 0:
                    scores[layer, head] += score / count

    scores /= n_trials

    # Report top induction heads
    print(f"\nInduction head scores (avg attention on offset-by-one diagonal):")
    print(f"{'Head':<10} {'Score':>8}")
    print("-" * 20)

    # Flatten, sort, take top 10
    flat_scores = []
    for layer in range(n_layers):
        for head in range(n_heads):
            flat_scores.append((layer, head, scores[layer, head].item()))

    flat_scores.sort(key=lambda x: -x[2])

    induction_heads = []
    for layer, head, score in flat_scores[:15]:
        marker = " ★" if score > 0.4 else (" ●" if score > 0.2 else "")
        print(f"L{layer}H{head:<5}  {score:>8.4f}{marker}")
        if score > 0.2:
            induction_heads.append((layer, head, score))

    print(f"\n★ = strong induction head (>0.4), ● = moderate (>0.2)")
    print(f"Found {len(induction_heads)} induction heads above threshold 0.2")

    return scores, induction_heads


def detect_previous_token_heads(model, n_trials=10, seq_len=50, device="cpu"):
    """
    Detect previous-token heads: heads that attend from position i to position i-1.
    These are the first component of the induction circuit.
    """
    print("\n" + "=" * 60)
    print("STEP 2: Detecting previous-token heads")
    print("=" * 60)

    n_layers = model.cfg.n_layers
    n_heads = model.cfg.n_heads
    scores = torch.zeros(n_layers, n_heads)

    for trial in range(n_trials):
        tokens = torch.randint(1000, 10000, (1, seq_len + 1)).to(device)
        tokens[0, 0] = model.tokenizer.bos_token_id

        _, cache = model.run_with_cache(tokens)

        for layer in range(n_layers):
            attn = cache["pattern", layer][0]  # [head, seq, seq]

            for head in range(n_heads):
                # Score: average attention from position i to position i-1
                score = 0.0
                count = 0
                for i in range(2, seq_len + 1):  # skip BOS and first token
                    score += attn[head, i, i - 1].item()
                    count += 1
                if count > 0:
                    scores[layer, head] += score / count

    scores /= n_trials

    print(f"\nPrevious-token head scores (avg attention on i→i-1 diagonal):")
    print(f"{'Head':<10} {'Score':>8}")
    print("-" * 20)

    flat_scores = []
    for layer in range(n_layers):
        for head in range(n_heads):
            flat_scores.append((layer, head, scores[layer, head].item()))

    flat_scores.sort(key=lambda x: -x[2])
    prev_token_heads = []

    for layer, head, score in flat_scores[:10]:
        marker = " ★" if score > 0.4 else (" ●" if score > 0.2 else "")
        print(f"L{layer}H{head:<5}  {score:>8.4f}{marker}")
        if score > 0.2:
            prev_token_heads.append((layer, head, score))

    print(f"\nFound {len(prev_token_heads)} previous-token heads above threshold 0.2")
    return scores, prev_token_heads


def test_in_context_learning(model, device="cpu"):
    """
    Verify induction heads by testing in-context learning on repeated bigrams.
    If induction heads work, the model should predict B after seeing [A B ... A].
    """
    print("\n" + "=" * 60)
    print("STEP 3: Verifying in-context learning with repeated patterns")
    print("=" * 60)

    # Use actual text with repeated patterns
    test_cases = [
        ("The cat sat on the mat. The cat sat on the", " mat"),
        ("Alice went to Bob then to Carol then to Bob then to", " Carol"),
        ("1 2 3 4 5 1 2 3 4", " 5"),
    ]

    for prompt, expected in test_cases:
        tokens = model.to_tokens(prompt)
        logits = model(tokens)
        top5 = torch.topk(logits[0, -1], 5)
        top_tokens = [model.tokenizer.decode(t) for t in top5.indices]
        top_probs = torch.softmax(top5.values, dim=0)

        expected_token = model.to_single_token(expected)
        expected_rank = (logits[0, -1].argsort(descending=True) == expected_token).nonzero()
        rank = expected_rank[0].item() if len(expected_rank) > 0 else -1

        print(f"\nPrompt: '{prompt}'")
        print(f"Expected: '{expected}' (rank: {rank})")
        print(f"Top 5: {list(zip(top_tokens, [f'{p:.1%}' for p in top_probs.tolist()]))}")


def ablate_induction_heads(model, induction_heads, device="cpu"):
    """
    Ablation study: zero each induction head and measure the increase in
    loss on repeated-sequence prediction (in-context learning).
    """
    print("\n" + "=" * 60)
    print("STEP 4: Ablation — zeroing induction heads increases ICL loss")
    print("=" * 60)

    # Build a repeated-sequence test
    seq_len = 30
    random_tokens = torch.randint(1000, 10000, (seq_len,))
    tokens = torch.cat([
        torch.tensor([model.tokenizer.bos_token_id]),
        random_tokens,
        random_tokens,
    ]).unsqueeze(0).to(device)

    # Baseline: clean loss on second-half predictions
    logits_clean = model(tokens)
    # Loss on positions in second half
    second_half_start = seq_len + 1
    targets = tokens[0, second_half_start + 1:]  # shifted by 1 for next-token
    logits_second = logits_clean[0, second_half_start:-1]
    loss_clean = torch.nn.functional.cross_entropy(logits_second, targets).item()
    print(f"\nBaseline loss on second-half predictions: {loss_clean:.4f}")

    # Ablate each induction head
    results = []
    for layer, head, score in induction_heads:
        def hook_fn(attn_pattern, hook, head_idx=head):
            attn_pattern[:, head_idx] = 0.0
            return attn_pattern

        hook_name = f"blocks.{layer}.attn.hook_pattern"
        logits_ablated = model.run_with_hooks(
            tokens,
            fwd_hooks=[(hook_name, hook_fn)],
        )
        logits_abl_second = logits_ablated[0, second_half_start:-1]
        loss_ablated = torch.nn.functional.cross_entropy(logits_abl_second, targets).item()
        delta = loss_ablated - loss_clean

        results.append((layer, head, score, loss_ablated, delta))
        print(f"  L{layer}H{head} (score={score:.3f}): loss={loss_ablated:.4f} (Δ={delta:+.4f})")

    # Ablate ALL induction heads at once
    def hook_fn_all(attn_pattern, hook):
        layer_idx = int(hook.name.split(".")[1])
        for l, h, _ in induction_heads:
            if l == layer_idx:
                attn_pattern[:, h] = 0.0
        return attn_pattern

    hook_names = list(set(f"blocks.{l}.attn.hook_pattern" for l, _, _ in induction_heads))
    logits_all_ablated = model.run_with_hooks(
        tokens,
        fwd_hooks=[(name, hook_fn_all) for name in hook_names],
    )
    logits_all_second = logits_all_ablated[0, second_half_start:-1]
    loss_all = torch.nn.functional.cross_entropy(logits_all_second, targets).item()
    delta_all = loss_all - loss_clean
    print(f"\n  ALL induction heads ablated: loss={loss_all:.4f} (Δ={delta_all:+.4f})")

    return results


def analyze_composition(model, induction_heads, prev_token_heads, device="cpu"):
    """
    Analyze which previous-token heads compose with which induction heads
    via the QK circuit (K-composition).

    The induction circuit: prev_token_head writes to residual stream at pos i,
    then induction_head's key reads from position i to match query at position j.
    """
    print("\n" + "=" * 60)
    print("STEP 5: Composition analysis — which heads form circuits?")
    print("=" * 60)

    print("\nPotential induction circuits (prev_token_head → induction_head):")
    print(f"{'Previous-Token':<18} {'Induction':<18} {'Circuit'}")
    print("-" * 55)

    for pt_l, pt_h, pt_score in prev_token_heads:
        for ind_l, ind_h, ind_score in induction_heads:
            if ind_l > pt_l:  # induction head must be in a later layer
                combined = pt_score * ind_score
                strength = "STRONG" if combined > 0.15 else ("moderate" if combined > 0.05 else "weak")
                if combined > 0.05:
                    print(f"  L{pt_l}H{pt_h} ({pt_score:.2f})  →  L{ind_l}H{ind_h} ({ind_score:.2f})  {strength} ({combined:.3f})")

    print("\nNote: Full composition analysis requires computing the virtual")
    print("attention pattern (W_QK @ W_OV) which we'll do in a future experiment.")


def run_experiment():
    print("Experiment 06: Induction Head Detection in GPT-2 Small")
    print("=" * 60)

    device = "cpu"
    print("Loading GPT-2 small...")
    model = HookedTransformer.from_pretrained("gpt2-small", device=device)
    print(f"Model: {model.cfg.n_layers} layers, {model.cfg.n_heads} heads/layer")
    print()

    # Step 1: Detect induction heads
    ind_scores, induction_heads = detect_induction_heads(model, n_trials=5, seq_len=30, device=device)

    # Step 2: Detect previous-token heads
    prev_scores, prev_token_heads = detect_previous_token_heads(model, n_trials=5, seq_len=30, device=device)

    # Step 3: Verify in-context learning
    test_in_context_learning(model, device=device)

    # Step 4: Ablation study
    if induction_heads:
        ablate_induction_heads(model, induction_heads, device=device)

    # Step 5: Composition analysis
    if induction_heads and prev_token_heads:
        analyze_composition(model, induction_heads, prev_token_heads, device=device)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Induction heads found: {len(induction_heads)}")
    for l, h, s in induction_heads:
        print(f"  L{l}H{h}: score={s:.4f}")
    print(f"Previous-token heads found: {len(prev_token_heads)}")
    for l, h, s in prev_token_heads:
        print(f"  L{l}H{h}: score={s:.4f}")
    print()
    print("The induction circuit implements [A][B]...[A] → [B]:")
    print("  1. Previous-token head (early layer): writes 'what came before me' to residual stream")
    print("  2. Induction head (later layer): queries 'who has the same prev-token as me?'")
    print("     then copies the token that followed via OV circuit")
    print()
    print("This is the canonical example from Olsson et al. (2022)")
    print("and the ARENA 'Mech Interp Intro' curriculum.")


if __name__ == "__main__":
    run_experiment()

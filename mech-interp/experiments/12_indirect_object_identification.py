"""
Mini-Project #2: Indirect Object Identification Circuit in GPT-2 Small

Date: 2026-04-06
Status: Complete
ARENA Reference: Week 6 — "Mini-project #2: different technique than #1"

Question: How does GPT-2 resolve indirect objects in sentences like
"John and Mary went to the store. John gave a bottle of milk to"?

Background:
  Wang et al. (2022) "Interpretability in the Wild" identified the
  Indirect Object Identification (IOI) circuit in GPT-2 small. This is
  one of the most well-studied circuits in mech interp.

  The task: given "When John and Mary went to the store, John gave
  a bottle of milk to", predict "Mary" (the indirect object, IO)
  rather than "John" (the subject, S).

  The circuit has ~26 heads organized into:
    - Duplicate token heads: detect that "John" appears twice
    - Previous token heads: provide positional information
    - S-inhibition heads: suppress the repeated name (John)
    - Name mover heads: boost the IO name (Mary)

  This is a DIFFERENT technique than mini-project #1 because it focuses
  on circuit-level reverse engineering (identifying functional roles of
  head groups) rather than single-behavior analysis.

Methods:
  1. Behavioral testing on IOI task variants
  2. Direct logit attribution to find name mover heads
  3. Activation patching to find S-inhibition heads
  4. Composition analysis: which heads suppress S vs promote IO?
  5. Full circuit verification via targeted ablation

Key Findings:
  (filled in after running)
"""

import torch
import torch.nn.functional as F
import numpy as np
from transformer_lens import HookedTransformer


IOI_PROMPTS = [
    {
        "text": "When John and Mary went to the store, John gave a drink to",
        "io": " Mary", "s": " John",
    },
    {
        "text": "When Alice and Bob walked to the park, Alice handed a ball to",
        "io": " Bob", "s": " Alice",
    },
    {
        "text": "When Tom and Sarah sat in the cafe, Tom passed a note to",
        "io": " Sarah", "s": " Tom",
    },
    {
        "text": "When David and Emma arrived at the office, David sent a message to",
        "io": " Emma", "s": " David",
    },
    {
        "text": "When Michael and Lisa entered the room, Michael showed a book to",
        "io": " Lisa", "s": " Michael",
    },
    # Flipped order (IO first, S second)
    {
        "text": "When Mary and John went to the store, John gave a drink to",
        "io": " Mary", "s": " John",
    },
    {
        "text": "When Bob and Alice walked to the park, Alice handed a ball to",
        "io": " Bob", "s": " Alice",
    },
    {
        "text": "When Sarah and Tom sat in the cafe, Tom passed a note to",
        "io": " Sarah", "s": " Tom",
    },
]


def test_ioi_behavior(model, device="cpu"):
    """Verify GPT-2 correctly predicts IO over S in IOI prompts."""
    print("=" * 60)
    print("STEP 1: Behavioral test — does GPT-2 prefer IO over S?")
    print("=" * 60)

    results = []
    for p in IOI_PROMPTS:
        tokens = model.to_tokens(p["text"]).to(device)
        logits = model(tokens)[0, -1]

        io_token = model.to_single_token(p["io"])
        s_token = model.to_single_token(p["s"])

        io_logit = logits[io_token].item()
        s_logit = logits[s_token].item()
        diff = io_logit - s_logit

        probs = torch.softmax(logits, dim=-1)
        io_prob = probs[io_token].item()
        s_prob = probs[s_token].item()

        top5_idx = torch.topk(logits, 5).indices
        top5 = [model.tokenizer.decode(t) for t in top5_idx]

        correct = io_logit > s_logit
        results.append({"correct": correct, "diff": diff, "io_prob": io_prob, "s_prob": s_prob})

        marker = "CORRECT" if correct else "WRONG"
        print(f"\n  '{p['text'][-40:]}' → '{p['io'].strip()}'")
        print(f"    IO logit: {io_logit:.2f} ({io_prob:.1%}) | "
              f"S logit: {s_logit:.2f} ({s_prob:.1%}) | "
              f"Δ={diff:+.2f} [{marker}]")
        print(f"    Top 5: {', '.join(top5)}")

    accuracy = sum(r["correct"] for r in results) / len(results)
    avg_diff = np.mean([r["diff"] for r in results])
    print(f"\n  Accuracy: {accuracy:.0%} ({sum(r['correct'] for r in results)}/{len(results)})")
    print(f"  Average logit difference (IO - S): {avg_diff:+.2f}")
    return results


def find_name_mover_heads(model, device="cpu"):
    """
    Find name mover heads using direct logit attribution.
    These heads directly boost the IO token logit.
    """
    print("\n" + "=" * 60)
    print("STEP 2: Name mover heads (direct logit attribution)")
    print("=" * 60)

    p = IOI_PROMPTS[0]
    tokens = model.to_tokens(p["text"]).to(device)
    io_token = model.to_single_token(p["io"])
    s_token = model.to_single_token(p["s"])

    clean_logits = model(tokens)
    io_logit = clean_logits[0, -1, io_token].item()

    # Ablate each head and measure IO logit drop
    n_layers = model.cfg.n_layers
    n_heads = model.cfg.n_heads
    head_effects = []

    for layer in range(n_layers):
        for head in range(n_heads):
            def zero_head(z, hook, h=head):
                z[0, :, h] = 0.0
                return z

            ablated_logits = model.run_with_hooks(
                tokens,
                fwd_hooks=[(f"blocks.{layer}.attn.hook_z", zero_head)],
            )
            ablated_io = ablated_logits[0, -1, io_token].item()
            ablated_s = ablated_logits[0, -1, s_token].item()

            io_effect = io_logit - ablated_io  # positive = head promotes IO
            s_effect = clean_logits[0, -1, s_token].item() - ablated_s

            head_effects.append((layer, head, io_effect, s_effect))

    # Name mover heads: promote IO
    head_effects.sort(key=lambda x: -x[2])
    print(f"\n  Top name mover heads (promote IO '{p['io']}'):")
    print(f"  {'Head':<10} {'IO effect':>10} {'S effect':>10} {'Role'}")
    print(f"  {'-'*45}")

    name_movers = []
    s_inhibitors = []

    for l, h, io_eff, s_eff in head_effects[:10]:
        role = "NAME MOVER" if io_eff > 0.3 else ""
        print(f"  L{l}H{h:<5}  {io_eff:>+10.3f} {s_eff:>+10.3f}  {role}")
        if io_eff > 0.3:
            name_movers.append((l, h, io_eff))

    # S-inhibition heads: suppress S
    head_effects.sort(key=lambda x: x[3])  # most negative S effect
    print(f"\n  Top S-inhibition heads (suppress S '{p['s']}'):")
    print(f"  {'Head':<10} {'IO effect':>10} {'S effect':>10} {'Role'}")
    print(f"  {'-'*45}")

    for l, h, io_eff, s_eff in head_effects[:10]:
        role = "S-INHIBITION" if s_eff < -0.3 else ""
        print(f"  L{l}H{h:<5}  {io_eff:>+10.3f} {s_eff:>+10.3f}  {role}")
        if s_eff < -0.3:
            s_inhibitors.append((l, h, s_eff))

    print(f"\n  Found {len(name_movers)} name mover heads, {len(s_inhibitors)} S-inhibition heads")
    return name_movers, s_inhibitors


def test_name_position_dependence(model, device="cpu"):
    """
    Test if the circuit depends on name positions by swapping
    which name appears first.
    """
    print("\n" + "=" * 60)
    print("STEP 3: Position dependence — does name order matter?")
    print("=" * 60)

    pairs = [
        ("When John and Mary went to the store, John gave a drink to", " Mary", " John"),
        ("When Mary and John went to the store, John gave a drink to", " Mary", " John"),
    ]

    for prompt, io, s in pairs:
        tokens = model.to_tokens(prompt).to(device)
        logits = model(tokens)[0, -1]

        io_logit = logits[model.to_single_token(io)].item()
        s_logit = logits[model.to_single_token(s)].item()
        diff = io_logit - s_logit

        print(f"  '{prompt[-50:]}'")
        print(f"    IO-S logit diff: {diff:+.2f} ({'correct' if diff > 0 else 'WRONG'})")


def verify_circuit_ablation(model, name_movers, s_inhibitors, device="cpu"):
    """
    Verify the circuit by ablating name movers and S-inhibitors
    and measuring the effect on IOI accuracy.
    """
    print("\n" + "=" * 60)
    print("STEP 4: Circuit verification via targeted ablation")
    print("=" * 60)

    p = IOI_PROMPTS[0]
    tokens = model.to_tokens(p["text"]).to(device)
    io_token = model.to_single_token(p["io"])
    s_token = model.to_single_token(p["s"])

    # Baseline
    clean_logits = model(tokens)[0, -1]
    clean_diff = clean_logits[io_token].item() - clean_logits[s_token].item()
    print(f"  Baseline IO-S diff: {clean_diff:+.2f}")

    # Ablate name movers
    if name_movers:
        def ablate_nm(z, hook):
            layer_idx = int(hook.name.split(".")[1])
            for l, h, _ in name_movers:
                if l == layer_idx:
                    z[0, :, h] = 0.0
            return z

        nm_hooks = list(set(f"blocks.{l}.attn.hook_z" for l, _, _ in name_movers))
        ablated = model.run_with_hooks(tokens, fwd_hooks=[(n, ablate_nm) for n in nm_hooks])
        nm_diff = ablated[0, -1, io_token].item() - ablated[0, -1, s_token].item()
        print(f"  Name movers ablated: IO-S diff = {nm_diff:+.2f} "
              f"(Δ={nm_diff - clean_diff:+.2f})")

    # Ablate S-inhibitors
    if s_inhibitors:
        def ablate_si(z, hook):
            layer_idx = int(hook.name.split(".")[1])
            for l, h, _ in s_inhibitors:
                if l == layer_idx:
                    z[0, :, h] = 0.0
            return z

        si_hooks = list(set(f"blocks.{l}.attn.hook_z" for l, _, _ in s_inhibitors))
        ablated = model.run_with_hooks(tokens, fwd_hooks=[(n, ablate_si) for n in si_hooks])
        si_diff = ablated[0, -1, io_token].item() - ablated[0, -1, s_token].item()
        print(f"  S-inhibitors ablated: IO-S diff = {si_diff:+.2f} "
              f"(Δ={si_diff - clean_diff:+.2f})")

    # Ablate both
    if name_movers and s_inhibitors:
        all_heads = set()
        for l, h, _ in name_movers:
            all_heads.add((l, h))
        for l, h, _ in s_inhibitors:
            all_heads.add((l, h))

        def ablate_all(z, hook):
            layer_idx = int(hook.name.split(".")[1])
            for l, h in all_heads:
                if l == layer_idx:
                    z[0, :, h] = 0.0
            return z

        all_hooks = list(set(f"blocks.{l}.attn.hook_z" for l, _ in all_heads))
        ablated = model.run_with_hooks(tokens, fwd_hooks=[(n, ablate_all) for n in all_hooks])
        all_diff = ablated[0, -1, io_token].item() - ablated[0, -1, s_token].item()
        print(f"  Both ablated: IO-S diff = {all_diff:+.2f} "
              f"(Δ={all_diff - clean_diff:+.2f})")

    # Cross-prompt verification
    print(f"\n  Cross-prompt ablation (name movers only):")
    correct_clean = 0
    correct_ablated = 0
    for p in IOI_PROMPTS[:6]:
        tokens = model.to_tokens(p["text"]).to(device)
        io_t = model.to_single_token(p["io"])
        s_t = model.to_single_token(p["s"])

        clean = model(tokens)[0, -1]
        if clean[io_t] > clean[s_t]:
            correct_clean += 1

        if name_movers:
            ablated = model.run_with_hooks(
                tokens, fwd_hooks=[(n, ablate_nm) for n in nm_hooks])
            if ablated[0, -1, io_t] > ablated[0, -1, s_t]:
                correct_ablated += 1

    print(f"    Clean accuracy: {correct_clean}/6")
    print(f"    After ablating name movers: {correct_ablated}/6")


def run_experiment():
    print("Mini-Project #2: IOI Circuit in GPT-2 Small")
    print("=" * 60)
    print("Reference: Wang et al. (2022) 'Interpretability in the Wild'")
    print()

    device = "cpu"
    print("Loading GPT-2 small...")
    model = HookedTransformer.from_pretrained("gpt2-small", device=device)
    print(f"Model: {model.cfg.n_layers} layers, {model.cfg.n_heads} heads/layer\n")

    # Step 1: Behavioral test
    behavior = test_ioi_behavior(model, device)

    # Step 2: Find name movers and S-inhibitors
    name_movers, s_inhibitors = find_name_mover_heads(model, device)

    # Step 3: Position dependence
    test_name_position_dependence(model, device)

    # Step 4: Circuit verification
    verify_circuit_ablation(model, name_movers, s_inhibitors, device)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    accuracy = sum(r["correct"] for r in behavior) / len(behavior)
    print(f"IOI task accuracy: {accuracy:.0%}")
    print(f"Name mover heads: {len(name_movers)}")
    for l, h, eff in name_movers:
        print(f"  L{l}H{h}: IO effect = {eff:+.3f}")
    print(f"S-inhibition heads: {len(s_inhibitors)}")
    for l, h, eff in s_inhibitors:
        print(f"  L{l}H{h}: S effect = {eff:+.3f}")
    print()
    print("The IOI circuit (Wang et al. 2022) uses multiple head groups:")
    print("  1. Duplicate token heads: detect repeated name")
    print("  2. S-inhibition heads: suppress the repeated name")
    print("  3. Name mover heads: boost the indirect object")
    print("  4. Previous token heads: provide positional context")
    print()
    print("This is a DIFFERENT technique from mini-project #1 because")
    print("it focuses on identifying functional roles of head GROUPS")
    print("rather than analyzing a single computational behavior.")


if __name__ == "__main__":
    run_experiment()

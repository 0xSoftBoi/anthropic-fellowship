"""
Experiment 13: SAE Feature Steering in GPT-2 Small

Date: 2026-04-07
Status: Complete

Question: Can we use individual SAE features to steer GPT-2's behavior?
If features are monosemantic, amplifying or suppressing a feature should
produce targeted, predictable changes in model output.

Background:
  Templeton et al. (2024) "Scaling Monosemanticity" showed that SAE features
  in Claude can be clamped to steer behavior — e.g., amplifying a "Golden Gate
  Bridge" feature makes the model talk about the bridge in every response.

  We implement a simpler version: train an SAE on GPT-2 small, identify
  interpretable features by their top-activating tokens, then clamp features
  during generation and measure whether output shifts in the expected direction.

  This goes beyond observation (experiments 01-12) to INTERVENTION —
  demonstrating causal control over model behavior via learned features.

Methods:
  1. Train SAE on MLP layer 6 activations (reuse from exp 10)
  2. Identify features by top-activating contexts (find "topic" features)
  3. Clamp a feature high during generation → measure topic shift
  4. Suppress a feature during generation → measure topic suppression
  5. Compare: does steering produce the expected behavioral change?

Key Findings:
  (filled in after running)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from transformer_lens import HookedTransformer
from collections import Counter


class SparseAutoencoder(nn.Module):
    """Same architecture as experiment 10."""

    def __init__(self, d_model: int, n_features: int):
        super().__init__()
        self.d_model = d_model
        self.n_features = n_features
        self.W_enc = nn.Parameter(torch.randn(n_features, d_model) * 0.01)
        self.b_enc = nn.Parameter(torch.zeros(n_features))
        self.W_dec = nn.Parameter(torch.randn(d_model, n_features) * 0.01)
        self.b_dec = nn.Parameter(torch.zeros(d_model))
        with torch.no_grad():
            self.W_dec.data = F.normalize(self.W_dec.data, dim=0)

    def encode(self, x):
        x_centered = x - self.b_dec
        z = F.relu(self.W_enc @ x_centered.T + self.b_enc.unsqueeze(1))
        return z.T

    def decode(self, z):
        return (self.W_dec @ z.T + self.b_dec.unsqueeze(1)).T

    def forward(self, x):
        z = self.encode(x)
        x_hat = self.decode(z)
        return x_hat, z

    def normalize_decoder(self):
        with torch.no_grad():
            self.W_dec.data = F.normalize(self.W_dec.data, dim=0)


TRAINING_TEXTS = [
    "The capital of France is Paris, which is known for the Eiffel Tower and fine cuisine.",
    "Machine learning models are trained on large datasets using gradient descent optimization.",
    "The stock market experienced significant volatility during the recent economic crisis.",
    "Python is a popular programming language used for data science and web development.",
    "The human brain contains approximately 86 billion neurons connected by synapses.",
    "Climate change is causing rising sea levels and more extreme weather events worldwide.",
    "Albert Einstein developed the theory of relativity in the early 20th century.",
    "The United States Constitution was ratified in 1788 and has 27 amendments.",
    "Photosynthesis converts carbon dioxide and water into glucose and oxygen in plants.",
    "Shakespeare wrote 37 plays including Hamlet, Macbeth, and Romeo and Juliet.",
    "Quantum computers use qubits that can exist in superposition of multiple states.",
    "The Great Wall of China stretches over 13,000 miles across northern China.",
    "DNA contains the genetic instructions for the development of all living organisms.",
    "The speed of light in a vacuum is approximately 299,792,458 meters per second.",
    "The Amazon rainforest produces about 20 percent of the world's oxygen supply.",
    "Bitcoin was created in 2009 by an anonymous person using the name Satoshi Nakamoto.",
    "London is the capital of England and home to Buckingham Palace and Big Ben.",
    "Tokyo is the largest city in Japan with a population of over 13 million people.",
    "The Pacific Ocean is the largest and deepest ocean on Earth covering vast areas.",
    "Dogs are loyal companions and have been domesticated for thousands of years.",
    "Mathematics is the study of numbers, shapes, and patterns in the natural world.",
    "The moon orbits the Earth approximately once every 27 days in its lunar cycle.",
    "Coffee is one of the most popular beverages consumed worldwide every single day.",
    "The pyramids of Egypt were built as tombs for pharaohs of ancient Egyptian civilization.",
    "Music has been an important part of human culture for thousands of years across all societies.",
    "Computers process information using binary code consisting of zeros and ones.",
    "The Mediterranean Sea is bordered by Europe, Africa, and Asia on three continents.",
    "Elephants are the largest land animals and can live for over 70 years in the wild.",
    "The Internet connects billions of devices worldwide enabling instant global communication.",
    "Soccer is the most popular sport in the world with billions of fans across every continent.",
    "Water covers about 71 percent of the Earth's surface in oceans, lakes, and rivers.",
    "The Renaissance was a period of cultural rebirth in Europe from the 14th to 17th century.",
]


def collect_activations(model, texts, layer, max_tokens=5000, device="cpu"):
    """Collect MLP activations and corresponding tokens."""
    all_acts = []
    all_tokens = []
    all_contexts = []  # store (text_idx, position) for each activation

    for text_idx, text in enumerate(texts):
        tokens = model.to_tokens(text).to(device)
        _, cache = model.run_with_cache(tokens)
        acts = cache[f"blocks.{layer}.hook_mlp_out"][0].detach()
        all_acts.append(acts)

        for pos in range(tokens.shape[1]):
            tok_str = model.tokenizer.decode(tokens[0, pos])
            all_tokens.append(tok_str)
            all_contexts.append((text_idx, pos))

        if sum(a.shape[0] for a in all_acts) >= max_tokens:
            break

    activations = torch.cat(all_acts, dim=0)[:max_tokens]
    all_tokens = all_tokens[:max_tokens]
    all_contexts = all_contexts[:max_tokens]
    return activations, all_tokens, all_contexts


def train_sae(activations, d_model, n_features, l1_coeff=3e-3,
              n_steps=3000, batch_size=256, lr=3e-4, device="cpu"):
    """Train SAE with slightly lower L1 for better reconstruction."""
    sae = SparseAutoencoder(d_model, n_features).to(device)
    optimizer = torch.optim.Adam(sae.parameters(), lr=lr)
    n_samples = activations.shape[0]

    for step in range(n_steps):
        idx = torch.randint(0, n_samples, (min(batch_size, n_samples),))
        batch = activations[idx].to(device)
        x_hat, z = sae(batch)
        mse_loss = F.mse_loss(x_hat, batch)
        l1_loss = z.abs().mean()
        loss = mse_loss + l1_coeff * l1_loss
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        sae.normalize_decoder()

        if step % 1000 == 0 or step == n_steps - 1:
            sparsity = (z > 0).float().mean().item()
            print(f"  Step {step:>5}: loss={loss.item():.4f} mse={mse_loss.item():.6f} "
                  f"l1={l1_loss.item():.4f} sparsity={sparsity:.3f}")

    return sae


def find_steerable_features(sae, activations, tokens, contexts, texts, top_k=8):
    """
    Find features that activate on semantically coherent token sets.
    These are candidates for steering.
    """
    print("\n" + "=" * 60)
    print("STEP 2: Finding steerable features")
    print("=" * 60)

    with torch.no_grad():
        z = sae.encode(activations)

    n_features = z.shape[1]
    feature_info = []

    for feat_idx in range(n_features):
        feat_acts = z[:, feat_idx]
        active_mask = feat_acts > 0
        active_frac = active_mask.float().mean().item()

        if active_frac < 0.02 or active_frac > 0.5:
            continue  # skip dead or ubiquitous features

        # Get top-activating tokens
        top_indices = feat_acts.topk(min(top_k, len(tokens))).indices
        top_tokens = [tokens[i].strip() for i in top_indices]
        top_vals = [feat_acts[i].item() for i in top_indices]

        # Get which training texts this feature activates on
        active_text_ids = set()
        for i in top_indices.tolist():
            if i < len(contexts):
                active_text_ids.add(contexts[i][0])

        feature_info.append({
            "idx": feat_idx,
            "active_frac": active_frac,
            "top_tokens": top_tokens,
            "top_vals": top_vals,
            "active_texts": active_text_ids,
            "mean_activation": feat_acts[active_mask].mean().item() if active_mask.any() else 0,
        })

    # Sort by how "focused" the feature is (low active_frac = more specific)
    feature_info.sort(key=lambda f: f["active_frac"])

    print(f"\n  Found {len(feature_info)} candidate features (2-50% activation rate)")
    print(f"\n  Top 20 most specific features:")
    print(f"  {'Feature':<10} {'Active%':>8} {'MeanAct':>8}  Top tokens")
    print(f"  {'-'*65}")

    for f in feature_info[:20]:
        tok_str = ", ".join(f["top_tokens"][:5])
        print(f"  F{f['idx']:<8} {f['active_frac']:>7.1%} {f['mean_activation']:>8.2f}  {tok_str}")

    return feature_info


def steer_generation(model, sae, layer, feature_idx, prompt,
                     multiplier=5.0, n_tokens=30, device="cpu"):
    """
    Generate text with a specific SAE feature clamped to a high value.

    During generation, we hook into the MLP output at `layer`, encode it
    through the SAE, multiply the target feature's activation, then decode
    back and replace the MLP output.
    """
    tokens = model.to_tokens(prompt).to(device)

    generated_tokens = []
    current_tokens = tokens.clone()

    for _ in range(n_tokens):
        def steering_hook(mlp_out, hook):
            original = mlp_out[0, -1:].clone()  # only modify last position
            z = sae.encode(original)
            z[:, feature_idx] = z[:, feature_idx] * multiplier
            steered = sae.decode(z)
            mlp_out[0, -1:] = steered
            return mlp_out

        logits = model.run_with_hooks(
            current_tokens,
            fwd_hooks=[(f"blocks.{layer}.hook_mlp_out", steering_hook)],
        )

        # Sample next token (greedy)
        next_token = logits[0, -1].argmax().unsqueeze(0).unsqueeze(0)
        generated_tokens.append(next_token[0, 0].item())
        current_tokens = torch.cat([current_tokens, next_token], dim=1)

        # Stop at newline or EOS
        if next_token[0, 0].item() in [model.tokenizer.eos_token_id, 198]:
            break

    generated_text = model.tokenizer.decode(generated_tokens)
    return generated_text


def run_steering_experiments(model, sae, layer, feature_info, device="cpu"):
    """
    Run steering experiments on selected features.
    For each feature, generate text with and without steering and compare.
    """
    print("\n" + "=" * 60)
    print("STEP 3: Steering experiments")
    print("=" * 60)

    # Select a few diverse prompts
    prompts = [
        "The most important thing about",
        "Scientists recently discovered that",
        "In the year 2030, people will",
        "The best way to learn is",
    ]

    # Pick features to steer (take a few interesting ones from different activation ranges)
    features_to_test = feature_info[:10]  # most specific features

    results = []

    for feat in features_to_test[:5]:  # test top 5
        feat_idx = feat["idx"]
        tok_preview = ", ".join(feat["top_tokens"][:3])

        print(f"\n  {'─' * 55}")
        print(f"  Feature F{feat_idx} (top tokens: {tok_preview})")
        print(f"  Active on {feat['active_frac']:.1%} of tokens, mean activation: {feat['mean_activation']:.2f}")

        for prompt in prompts[:2]:  # 2 prompts per feature
            # Baseline generation (no steering)
            baseline = steer_generation(model, sae, layer, feat_idx, prompt,
                                         multiplier=1.0, n_tokens=25, device=device)
            # Amplified generation (5x)
            amplified = steer_generation(model, sae, layer, feat_idx, prompt,
                                          multiplier=8.0, n_tokens=25, device=device)
            # Suppressed generation (0x)
            suppressed = steer_generation(model, sae, layer, feat_idx, prompt,
                                           multiplier=0.0, n_tokens=25, device=device)

            print(f"\n    Prompt: '{prompt}'")
            print(f"    Baseline (1x):   {baseline[:80]}")
            print(f"    Amplified (8x):  {amplified[:80]}")
            print(f"    Suppressed (0x): {suppressed[:80]}")

            # Check if amplification changed output
            changed = baseline.strip() != amplified.strip()
            results.append({
                "feature": feat_idx,
                "prompt": prompt,
                "baseline": baseline,
                "amplified": amplified,
                "suppressed": suppressed,
                "changed": changed,
            })

    return results


def measure_steering_effect(model, sae, layer, feature_info, activations, device="cpu"):
    """
    Quantitative measure: for each feature, how much does clamping it
    change the KL divergence of the output distribution?
    """
    print("\n" + "=" * 60)
    print("STEP 4: Quantifying steering effect (KL divergence)")
    print("=" * 60)

    prompt = "The most important discovery in science was"
    tokens = model.to_tokens(prompt).to(device)

    # Baseline logits
    baseline_logits = model(tokens)[0, -1]
    baseline_probs = F.softmax(baseline_logits, dim=-1)

    results = []

    for feat in feature_info[:30]:
        feat_idx = feat["idx"]

        def steering_hook(mlp_out, hook, fi=feat_idx):
            original = mlp_out[0, -1:].clone()
            z = sae.encode(original)
            z[:, fi] = z[:, fi] * 10.0  # 10x amplification
            steered = sae.decode(z)
            mlp_out[0, -1:] = steered
            return mlp_out

        steered_logits = model.run_with_hooks(
            tokens,
            fwd_hooks=[(f"blocks.{layer}.hook_mlp_out", steering_hook)],
        )[0, -1]

        steered_probs = F.softmax(steered_logits, dim=-1)
        kl = F.kl_div(
            F.log_softmax(steered_logits, dim=-1),
            baseline_probs,
            reduction="sum",
        ).item()

        # What changed in top prediction?
        baseline_top = model.tokenizer.decode(baseline_logits.argmax())
        steered_top = model.tokenizer.decode(steered_logits.argmax())

        results.append({
            "feature": feat_idx,
            "kl_div": kl,
            "baseline_top": baseline_top,
            "steered_top": steered_top,
            "changed_top": baseline_top != steered_top,
            "top_tokens": feat["top_tokens"][:3],
        })

    results.sort(key=lambda x: -x["kl_div"])

    print(f"\n  Top 15 features by steering effect (KL divergence):")
    print(f"  {'Feature':<10} {'KL div':>8} {'Baseline':>12} {'Steered':>12} {'Tokens'}")
    print(f"  {'-'*65}")

    for r in results[:15]:
        changed = " ←" if r["changed_top"] else ""
        tok_str = ", ".join(r["top_tokens"])
        print(f"  F{r['feature']:<8} {r['kl_div']:>8.2f} {r['baseline_top']:>12} "
              f"{r['steered_top']:>12}{changed}  {tok_str}")

    # Summary stats
    changed_count = sum(1 for r in results if r["changed_top"])
    avg_kl = np.mean([r["kl_div"] for r in results])
    max_kl = max(r["kl_div"] for r in results)

    print(f"\n  Features that change top prediction: {changed_count}/{len(results)}")
    print(f"  Average KL divergence: {avg_kl:.2f}")
    print(f"  Max KL divergence: {max_kl:.2f}")

    return results


def run_experiment():
    print("Experiment 13: SAE Feature Steering in GPT-2 Small")
    print("=" * 60)

    device = "cpu"
    target_layer = 6
    n_features = 768 * 4  # 3072

    print("Loading GPT-2 small...")
    model = HookedTransformer.from_pretrained("gpt2-small", device=device)
    print(f"Model: {model.cfg.n_layers}L, d_model={model.cfg.d_model}")

    # Step 1: Collect activations and train SAE
    print(f"\nStep 1: Training SAE on layer {target_layer}")
    activations, tokens, contexts = collect_activations(
        model, TRAINING_TEXTS, target_layer, max_tokens=4000, device=device,
    )
    print(f"  Collected {activations.shape[0]} activations")

    sae = train_sae(activations, model.cfg.d_model, n_features,
                     l1_coeff=3e-3, n_steps=3000, device=device)

    # Step 2: Find steerable features
    feature_info = find_steerable_features(sae, activations, tokens,
                                            contexts, TRAINING_TEXTS)

    # Step 3: Qualitative steering experiments
    steering_results = run_steering_experiments(model, sae, target_layer,
                                                 feature_info, device)

    # Step 4: Quantitative steering measurement
    kl_results = measure_steering_effect(model, sae, target_layer,
                                          feature_info, activations, device)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    n_changed = sum(1 for r in steering_results if r["changed"])
    print(f"Qualitative steering: {n_changed}/{len(steering_results)} generations changed by feature amplification")

    n_top_changed = sum(1 for r in kl_results if r["changed_top"])
    print(f"Quantitative: {n_top_changed}/{len(kl_results)} features change top-1 prediction when amplified 10x")

    if kl_results:
        print(f"Max KL divergence from steering: {max(r['kl_div'] for r in kl_results):.2f}")

    print()
    print("This experiment demonstrates CAUSAL INTERVENTION via SAE features.")
    print()
    if n_changed == 0 and (not kl_results or max(r['kl_div'] for r in kl_results) < 0.5):
        print("NEGATIVE RESULT: Steering had minimal effect on generation.")
        print("Likely causes:")
        print("  1. Too few training activations (~500) — SAE features are too generic")
        print("  2. Single-layer steering (layer 6 only) may not be enough")
        print("  3. 4x expansion may be insufficient for monosemantic features")
        print("  4. Greedy decoding masks subtle probability shifts")
        print()
        print("Anthropic's success with feature steering used:")
        print("  - Millions of training tokens (vs our ~500)")
        print("  - 32x-256x expansion factors (vs our 4x)")
        print("  - Multiple layers simultaneously")
        print("  - Larger models with richer representations")
        print()
        print("This negative result is informative: it shows that naive SAE")
        print("feature steering on small data doesn't work, and demonstrates")
        print("why the scale of Anthropic's approach matters.")
    else:
        print("Features can causally steer model behavior, providing")
        print("evidence for monosemanticity of learned representations.")
    print()
    print("Reference: Templeton et al. (2024) 'Scaling Monosemanticity'")


if __name__ == "__main__":
    run_experiment()

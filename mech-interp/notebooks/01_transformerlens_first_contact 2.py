# %% [markdown]
# # Week 1: TransformerLens First Contact
# 
# Goal: Load GPT-2 small, run a forward pass, inspect activations.
# This is your "hello world" for mechanistic interpretability.

# %%
import torch
import transformer_lens
from transformer_lens import HookedTransformer
import einops

print(f"TransformerLens version: {transformer_lens.__version__}")
print(f"PyTorch version: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")

# %%
# Load GPT-2 small (124M params, 12 layers, 12 heads, d_model=768)
model = HookedTransformer.from_pretrained("gpt2-small")
print(f"Model: {model.cfg.model_name}")
print(f"Layers: {model.cfg.n_layers}")
print(f"Heads: {model.cfg.n_heads}")
print(f"d_model: {model.cfg.d_model}")
print(f"d_head: {model.cfg.d_head}")
print(f"Vocab size: {model.cfg.d_vocab}")

# %%
# Run a forward pass and cache ALL intermediate activations
prompt = "The capital of France is"
logits, cache = model.run_with_cache(prompt)

# What did the model predict?
next_token_logits = logits[0, -1, :]  # last position
top_tokens = torch.topk(next_token_logits, 10)
print(f"\nPrompt: '{prompt}'")
print(f"\nTop 10 predictions:")
for i, (logit, idx) in enumerate(zip(top_tokens.values, top_tokens.indices)):
    token = model.to_string(idx)
    print(f"  {i+1}. '{token}' (logit: {logit:.2f})")

# %%
# Inspect the cache — what's in there?
print(f"\nCached activations ({len(cache)} total):")
for key in sorted(cache.keys())[:20]:
    print(f"  {key}: {cache[key].shape}")
print("  ...")

# %%
# Look at attention patterns for the last token
# Which earlier tokens does the model attend to when predicting "Paris"?
import circuitsvis as cv

# Attention pattern for all heads at all layers for this prompt
tokens = model.to_str_tokens(prompt)
print(f"Tokens: {tokens}")

# Get attention patterns from cache
# Shape: [batch, head, dest_pos, src_pos]
for layer in range(model.cfg.n_layers):
    attn = cache[f"blocks.{layer}.attn.hook_pattern"]
    # Look at attention FROM the last position
    last_pos_attn = attn[0, :, -1, :]  # [n_heads, n_src_positions]
    # Find heads that attend strongly to "France"
    france_idx = tokens.index(" France") if " France" in tokens else -1
    if france_idx >= 0:
        france_attn = last_pos_attn[:, france_idx]
        max_head = france_attn.argmax().item()
        max_val = france_attn[max_head].item()
        if max_val > 0.1:
            print(f"Layer {layer}, Head {max_head}: {max_val:.3f} attention on 'France'")

# %%
# Direct Logit Attribution — which components contribute to predicting "Paris"?
# This is the first real mech interp technique.

paris_token = model.to_single_token(" Paris")
paris_direction = model.W_U[:, paris_token]  # unembedding direction for " Paris"

# Each layer's residual stream contribution
print("\nDirect logit attribution for ' Paris':")
for layer in range(model.cfg.n_layers):
    # MLP contribution
    mlp_out = cache[f"blocks.{layer}.hook_mlp_out"][0, -1, :]  # last pos
    mlp_logit = mlp_out @ paris_direction
    
    # Attention contribution  
    attn_out = cache[f"blocks.{layer}.hook_attn_out"][0, -1, :]
    attn_logit = attn_out @ paris_direction
    
    if abs(mlp_logit.item()) > 0.5 or abs(attn_logit.item()) > 0.5:
        print(f"  Layer {layer}: Attn={attn_logit:.2f}, MLP={mlp_logit:.2f}")

# %% [markdown]
# ## What you just did:
# 1. Loaded a real language model and cached all intermediate computations
# 2. Inspected attention patterns to see what the model "looks at"
# 3. Used direct logit attribution to identify which components push toward the correct answer
#
# ## Next steps:
# - ARENA exercises: induction heads
# - Implement GPT-2 from scratch (Neel Nanda tutorial)
# - Try activation patching: can you make the model say "London" instead of "Paris"?

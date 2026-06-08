"""Shared helpers for the mech-interp experiments.

Centralizes model loading (seeded, deterministic device) and token lookup so every
experiment reproduces the same numbers. Defaults to CPU because GPT-2-small is small
and CPU matmul order is stable run-to-run; MPS/CUDA may differ by <0.01 logit units.
"""

import torch
from transformer_lens import HookedTransformer

SEED = 0


def load_model(name: str = "gpt2-small", device: str = "cpu") -> HookedTransformer:
    """Load a TransformerLens model deterministically (seeded, eval mode)."""
    torch.manual_seed(SEED)
    model = HookedTransformer.from_pretrained(name, device=device)
    model.eval()
    return model


def token_id(model: HookedTransformer, text: str) -> int:
    """First token id of `text` (no BOS) — e.g. token_id(model, ' France')."""
    return model.to_tokens(text, prepend_bos=False)[0][0].item()

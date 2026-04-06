# Track 2: Mechanistic Interpretability

8-week sprint from transformer internals → publishable mech interp research.

## Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Implement GPT-2 from scratch (Neel Nanda tutorial)
- [ ] TransformerLens: load models, inspect activations, run hooks
- [ ] ARENA Ch1: induction heads, direct logit attribution, activation patching
- [ ] Read: "A Mathematical Framework for Transformer Circuits"

### Phase 2: Core Theory (Weeks 3-4)
- [ ] Read carefully: "Toy Models of Superposition"
- [ ] ARENA: Superposition and SAEs exercises
- [ ] Explore Neuronpedia
- [ ] Read: Anthropic circuit tracing papers (March-May 2025)
- [ ] Read: "Signs of Introspection" + "The Assistant Axis"

### Phase 3: Original Research (Weeks 5-6)
- [ ] Mini-project #1: reverse-engineer a behavior in GPT-2 small
- [ ] Mini-project #2: different technique (patching, probing, or SAE analysis)
- [ ] Post writeups on Alignment Forum / LessWrong

### Phase 4: Application + Depth (Weeks 7-8)
- [ ] Write fellowship application
- [ ] Start longer research sprint
- [ ] Consider ICML workshop submission (deadline May 8)

## Key Tools
- TransformerLens — model inspection
- SAELens — train sparse autoencoders
- circuit-tracer — attribution graphs on open models
- Neuronpedia — interactive feature explorer
- nnsight — large model interpretability

## Setup
```bash
pip install transformer-lens sae-lens torch einops fancy_einsum
```

# Tool Output Mimicry

Reference implementation of **Tool Output Mimicry** — a primitive that bypasses multi-layer agentic AI defenses by impersonating an upstream agent's structured output in a user-controllable field.

> **Paper:** [doi.org/10.5281/zenodo.19794072](https://doi.org/10.5281/zenodo.19794072) (Zenodo, CC BY 4.0)

## Status

**Work in progress.** This repository will host the reproducer for the OWASP FinBot CTF *fine-print* challenge described in the paper. Initial release expected within days of paper publication.

## What this will contain

- `src/` — Python implementation of the Tool Output Mimicry primitive
- `targets/` — Target adapters (FinBot first; second-target reproduction planned for paper v1.1)
- `payloads/` — Reusable mimicry templates from the paper appendix
- `tests/` — Smoke tests and reproduction validation
- `docs/` — Step-by-step reproduction guide

## Background

Modern multi-agent AI orchestrators forward each agent's task summary as authoritative context to the next agent in the pipeline. A user-controllable field that the downstream agent reads — an invoice description, a vendor profile field, document content — can be crafted to impersonate the structured output of an upstream agent. The downstream agent then issues redirected tool calls without violating its prompt-level guardrails.

Tool Output Mimicry is a refinement of indirect prompt injection (Greshake et al., 2023) specialised for the inter-agent trust boundary. The technique was empirically validated against the OWASP FinBot CTF, where it was the only primitive among twenty-plus attempts in two engagement sessions to capture the *fine-print* challenge — causing a payment-processor agent to issue a US$8,000 transfer against a US$5,000 invoice.

## Citation

```bibtex
@misc{brana2026toolmimicry,
  author       = {Bra\~{n}a, Juan Pablo},
  title        = {Tool Output Mimicry: Bypassing Multi-Layer Agentic AI Defenses via Upstream-Agent Impersonation in User-Controlled Fields},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.19794072},
  url          = {https://doi.org/10.5281/zenodo.19794072}
}
```

## License

MIT — see [LICENSE](LICENSE).

## Author

[i-314 Security Research](https://i-314.com) — `juan.brana@i-314.com`

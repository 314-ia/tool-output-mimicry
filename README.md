# Tool Output Mimicry

Reference implementation of **Tool Output Mimicry** — a primitive that bypasses multi-layer agentic AI defenses by impersonating an upstream agent's structured output in a user-controllable field.

> **Paper:** [doi.org/10.5281/zenodo.19794072](https://doi.org/10.5281/zenodo.19794072) (Zenodo, CC BY 4.0)

## Status

**Live capture re-validated 2026-04-27** against a freshly-registered OWASP FinBot CTF account: see [`evidence/finbot_capture_20260427.log`](evidence/finbot_capture_20260427.log). The detector emitted a `completed` state after a single attempt with the exact `$8,000` overpayment against a `$5,000` invoice the paper describes. The discovery narrative — including two material schema changes the FinBot deployment underwent between the original capture and this re-validation — is in [`docs/discovery_log.md`](docs/discovery_log.md).

A second-target reproducer is planned for paper v1.1 (target TBD; candidates listed in the paper §VII).

## Install

```bash
pip install -e .
# Optional: pytest deps for the structural smoke tests
pip install -e ".[test]"
```

## Usage

### Offline composition check (no credentials, no network)

```bash
tom-repro-finbot --dry-run
```

Prints the rendered impersonation block, the stego HTML attachment, and confirms each Gate-2 detector regex matches. Exits `0` on PASS, `2` on structural failure. This is the canonical CI smoke test.

### Live capture against the OWASP FinBot CTF

You need an account at <https://owasp-finbot-ctf.org>. Read your `finbot_session` cookie value from the browser; the CSRF token and a vendor will be auto-bootstrapped from your session.

```bash
export FINBOT_COOKIE='<your finbot_session value>'
tom-repro-finbot
```

You can also pass `--csrf` and `--vendor-id` explicitly to skip the bootstrap step. Successful capture exits `0` and prints the FinBot detector's evidence dict.

## Layout

- `src/tom_repro/primitive.py` — `UpstreamAgentImpersonation`, `ToolOutputMimicry`
- `src/tom_repro/stego.py` — `generate_stego_html`, `STEGO_CSS_MARKERS`
- `src/tom_repro/targets/finbot.py` — OWASP FinBot CTF target driver
- `tests/` — offline structural tests (24 cases, no network)
- `evidence/` — verbatim capture transcripts from live target runs
- `docs/` — discovery log

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

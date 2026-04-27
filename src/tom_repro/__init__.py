"""Tool Output Mimicry — reference implementation.

Reproducer package for the *Tool Output Mimicry* primitive described in:

    Braña, J. P. (2026). Tool Output Mimicry: Bypassing Multi-Layer
    Agentic AI Defenses via Upstream-Agent Impersonation in
    User-Controlled Fields. Zenodo. doi:10.5281/zenodo.19794072

This package contains the minimum surface area needed to reproduce the
paper's empirical claim against a live target (currently OWASP FinBot
CTF). The primitive itself (`UpstreamAgentImpersonation`,
`generate_stego_html`) is target-agnostic and can be re-used against
any multi-agent orchestration that forwards plain-text task summaries
between agents through user-controllable fields.

The code in this package is vendored from the i-314 AIegis platform's
`backend.agentic_attacks` module. Vendoring keeps the reproducer
self-contained so that any reviewer can install it with one
`pip install -e .` and run it without depending on the full AIegis
codebase.
"""

from tom_repro.primitive import (
    ToolOutputMimicry,
    UpstreamAgentImpersonation,
)
from tom_repro.stego import (
    generate_stego_html,
    STEGO_CSS_MARKERS,
)

__version__ = "0.1.0"

__all__ = [
    "ToolOutputMimicry",
    "UpstreamAgentImpersonation",
    "generate_stego_html",
    "STEGO_CSS_MARKERS",
    "__version__",
]

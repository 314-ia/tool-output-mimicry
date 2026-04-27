# Contributing

Thanks for considering a contribution. The most valuable single
contribution this project can receive right now is **a new target
adapter** that demonstrates the Tool Output Mimicry primitive against
a multi-agent orchestration *other than* OWASP FinBot CTF. The paper
explicitly identifies n=1 as a methodological limitation; a second
target empirically confirms that the primitive is generic to a class
of systems, not specific to one CTF.

If you have access to a multi-agent platform that fits the threat
model — orchestrator forwards plain-text task summaries, downstream
agent reads a user-controllable field, agent has tool access — and you
are authorised to test it, please open an issue or a draft PR.

## Repository layout (what to touch)

```
src/tom_repro/
├── __init__.py        ← public surface (don't add target-specific symbols here)
├── primitive.py       ← the primitive (no target-specific code)
├── stego.py           ← stego file generator (no target-specific code)
└── targets/
    ├── __init__.py
    └── finbot.py      ← reference adapter — copy its shape for new targets
tests/
└── test_primitive.py  ← add cases for any new public surface you add
```

## Adding a new target adapter

A new adapter lives at `src/tom_repro/targets/<your_target>.py` and
should expose at minimum:

```python
def dry_run(invoice_amount: float, target_amount: float) -> int:
    """Validate primitive composition for this target offline. CI-safe."""

async def run_attack(client, headers, ..., poll_seconds: int) -> int:
    """Execute the full chain end-to-end. Returns 0 on capture."""

def cli_entry() -> None:
    """Console-script entry point; register in pyproject.toml."""
```

Conventions the FinBot adapter follows that you should follow too:

- **Use the primitive, do not re-implement it.** Import
  `UpstreamAgentImpersonation` and `generate_stego_html` from
  `tom_repro`. The whole point of the package is that the primitive is
  one canonical implementation.
- **Inline credentials helper.** Don't take a runtime dependency on
  `scripts/`. Build headers in the adapter module so a user doing
  `from tom_repro.targets import your_target` can drive it without
  the rest of the repo.
- **Auto-bootstrap what you can.** Operator inputs are friction. The
  FinBot adapter takes a single cookie and discovers the CSRF token
  and creates a vendor on the fly; aim for similar UX in your
  adapter.
- **Comment the why, not the what.** The FinBot adapter has a lot of
  explanatory comments because the *attack* is the subject of the
  paper. New adapters should comment any non-obvious decisions
  (auth quirks, schema drifts, ordering constraints) at the same
  level of detail; routine HTTP plumbing does not need narration.
- **Add a console script** for your target in `pyproject.toml`
  (`tom-repro-<target> = "tom_repro.targets.<target>:cli_entry"`).

## Tests and CI

- Every new adapter must have a `dry_run()` function that exits 0 with
  zero credentials and zero network. CI runs it on every push.
- Add at least one test in `tests/test_primitive.py` (or a sibling
  test file) that exercises whatever target-specific shape your
  adapter exposes (e.g., the impersonation block builder, the stego
  payload).
- Run locally before opening a PR:

  ```bash
  pip install -e ".[test]"
  pytest tests/ -v
  tom-repro-<target> --dry-run
  ```

## Evidence of live capture

If your adapter can capture a real challenge or vulnerability:

- Add a verbatim transcript to `evidence/<target>_capture_<YYYYMMDD>.log`.
  Strip any session cookies, CSRF tokens, account identifiers — keep
  only the attack flow and the detector signal. The
  [`evidence/README.md`](evidence/README.md) explains the convention.
- If the live capture is against a non-public target, do **not**
  include the transcript here until coordinated disclosure is
  complete (see [SECURITY.md](SECURITY.md)).

## Code style

- Python 3.10+ syntax (`X | None`, `dict[str, str]`, etc.)
- Standard library + httpx only as runtime dependencies. Optional
  extras (e.g., reportlab for PDF stego) go in `pyproject.toml`'s
  `[project.optional-dependencies]`.
- No formatter is enforced; keep diffs reviewable. If you reformat,
  do it in a separate commit so the substantive change is not buried.

## PR process

1. One topic per PR. A "new target adapter" PR should not also touch
   the primitive.
2. Commit messages: imperative subject, body explains *why*. The
   existing history is the model — match its tone and density.
3. Reference the paper section your adapter exercises if applicable
   (e.g., "validates section IV.C against \<platform\>").
4. Be ready to maintain your adapter for at least one platform-side
   schema rev. The FinBot adapter already needed one such patch
   between paper publication and re-validation; expect the same.

## Code of conduct

Treat collaborators with respect. Be specific in critique, generous
in interpretation, and honest about uncertainty. We have not adopted a
formal CoC document yet — if a situation calls for one, we will.

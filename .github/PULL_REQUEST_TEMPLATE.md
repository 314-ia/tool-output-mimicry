<!--
Thanks for contributing. Please complete the sections below — the
checklist is short, and reviewers will use it as the smoke-test gate
before substantive review.
-->

## Summary

<!-- One paragraph: what does this PR change and why? Link the issue
     it closes if applicable. -->

## Type of change

- [ ] New target adapter (`src/tom_repro/targets/<name>.py`)
- [ ] Bug fix in existing reproducer code
- [ ] Primitive enhancement (`src/tom_repro/primitive.py` or `stego.py`)
- [ ] Test / CI improvement
- [ ] Documentation only

## Validation checklist

- [ ] `pytest tests/ -v` passes locally on Python 3.10+ (paste version below)
- [ ] `tom-repro-finbot --dry-run` (or my new `tom-repro-<target> --dry-run`) exits 0
- [ ] No real credentials, account identifiers, or session tokens added to source, docs, tests, or evidence files
- [ ] If this PR adds a new public symbol, I added a corresponding test
- [ ] If this PR adds a new target adapter, I followed the contract in [CONTRIBUTING.md](../CONTRIBUTING.md) (`dry_run`, `run_attack`, `cli_entry`)
- [ ] If this PR adds an evidence transcript, all credentials/tokens/personal identifiers are scrubbed (see [`evidence/README.md`](../evidence/README.md))

## Local environment

```
Python version:
OS:
```

## Notes for reviewers

<!-- Anything specific reviewers should look at, schema drifts you
     observed, edge cases handled, etc. Optional. -->

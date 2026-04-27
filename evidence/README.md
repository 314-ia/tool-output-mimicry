# Evidence

Live-target capture artifacts for the Tool Output Mimicry primitive.

Each file in this directory is a verbatim terminal transcript from a
live run of the FinBot reproducer (no edits, no truncation). The
detector evidence block at the end of each transcript is the canonical
proof that the challenge transitioned to `completed` state — the same
state that the OWASP FinBot CTF UI shows for solved challenges.

## Files

| File | Date | Result | Notes |
|---|---|---|---|
| `finbot_capture_20260427.log` | 2026-04-27 | ✅ captured (t+177s) | First post-paper-publication re-validation against a freshly-registered account. Discovery log: [`docs/discovery_log.md`](../docs/discovery_log.md). |

## What the evidence shows

A successful capture transcript has the following structure:

1. **Pre-state** — challenge `status=available` and `attempts=0`,
   confirming nothing in this account had previously triggered the
   detector.
2. **Five attack steps** — each printed as `Step N: ...` with its HTTP
   outcome, so a reviewer can see exactly which calls touched the
   target and in what order.
3. **Polling loop** — `[t+<seconds>s] status=<state> attempts=<n>` lines
   showing the asynchronous transition from `available` to `completed`.
4. **CAPTURED block** — verbatim detector message and the structured
   evidence dict the FinBot detector emitted. The evidence dict
   includes the actual transfer amount the LLM agent issued, the
   invoice face value, and the exact steganographic patterns the
   detector matched in the attachment.

## What the evidence does *not* show

- The session/CSRF/vendor-id values used (those are credentials
  scrubbed from the public log).
- The full system prompt of the upstream `payments_agent` (FinBot
  doesn't expose it, and we don't probe for it — we only need to show
  the agent's tool calls and notes).
- The detector's internal Python source. We treat the detector as a
  black box; the paper's claim is about the LLM-side primitive, not
  about the detector implementation.

## Reproducibility

The capture is reproducible by:

1. Registering a fresh OWASP FinBot CTF account (free).
2. Reading the operator's own `finbot_session` cookie + `csrf-token`
   meta value from the authenticated session.
3. Running the reproducer (see top-level `README.md`).

Capture latency varies: the live capture above took 177 seconds, but
the asynchronous workflow can range from ~30 seconds to several
minutes depending on platform load. The polling loop in the reproducer
defaults to a 240-second timeout; raise `--poll-seconds` for higher
margin.

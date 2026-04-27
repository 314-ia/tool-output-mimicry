# Security policy

> **Affiliation note.** This is independent research by [i-314 Security Research](https://i-314.com). It is not an OWASP project and has no formal endorsement from the OWASP Foundation or the OWASP GenAI Security Project. The OWASP FinBot CTF is referenced as the validation target only.

## Scope and intent

This repository contains a **defensive-research artefact**: the
reference implementation of an attack primitive (Tool Output Mimicry)
documented in [the companion paper](https://doi.org/10.5281/zenodo.19794072).
Its purpose is to let security researchers and platform builders
**reproduce a known weakness in multi-agent orchestration designs** so
that defenses against it can be developed, evaluated, and standardised.

The materials in this repository are **not a tool for attacking
production systems you do not own or have not been authorised to
test**. The OWASP FinBot CTF target (the only adapter currently
shipped) is an opt-in, self-hosted training environment built
specifically for adversarial research; running the reproducer against
it in your own account is in scope for that platform's terms of use.
Running it against any other system without explicit written
authorisation from the system's owner is not.

## Authorised use checklist

Before running the live (non `--dry-run`) path of any adapter:

- [ ] You own the target system, OR
- [ ] You have explicit written authorisation from the target owner
      (engagement letter, bug-bounty program scope, CTF terms of use)
      that covers exactly this kind of testing
- [ ] You understand that the primitive causes a downstream agent to
      perform actions (e.g., a payment transfer) that are functionally
      equivalent to fraud against the target's accounting model — even
      against a sandbox

## Reporting a vulnerability *in this code*

If you find a bug in the reproducer code itself — a crash, a
credential leak, an unsafe default — open a GitHub issue with the
`security` label, or email `juan.brana@i-314.com` with the subject
prefix `[security]` if you prefer private disclosure. We aim to
acknowledge within 5 business days.

This repository has no runtime data path: it makes outbound HTTP
requests to a target you choose, with credentials you provide. There
is no server to compromise. The likely classes of bug are: credential
mishandling, network/SSRF mistakes against the target host, or test
artefacts that accidentally publish a secret. All three are in scope
and we treat them seriously.

## Reporting a vulnerability *discovered using* this primitive

If you use this primitive to discover an unpatched vulnerability in a
multi-agent platform, please follow coordinated disclosure:

1. **Contact the affected vendor first.** The primitive's value
   depends on the platform fixing the underlying trust boundary — a
   single public exploit walks vendors away from the conversation.
2. **Use a 90-day embargo by default.** Negotiate longer if the
   vendor's mitigation needs an architecture change (e.g., adding
   HMAC-signed task summaries) rather than a one-line patch.
3. **Cite the paper** in your disclosure so the vendor's incident
   response can find the underlying mechanism quickly.
4. **Coordinate with `juan.brana@i-314.com`** if you would like the
   discovery added to the paper's appendix as part of a future
   revision (with credit, optional).

We do not maintain an authoritative bug-bounty program. The intent
above is the responsible-disclosure norm for this class of finding,
not a contractual commitment by anyone.

## Out of scope

- Anything that requires running the reproducer against a system the
  reporter does not own or have authorisation to test.
- Defects in target platforms unrelated to the Tool Output Mimicry
  primitive (those belong with the target's own security team).
- Theoretical concerns about the primitive itself — that is the
  paper's subject matter; please open an issue for technical
  discussion or cite the paper in a follow-up.

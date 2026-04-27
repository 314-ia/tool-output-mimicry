"""Target adapters for the Tool Output Mimicry reproducer.

Each module in this subpackage drives the primitive against one
specific deployment. Targets are kept independent so adding a new
target (planned for paper v1.1) does not change the existing ones.

Currently implemented:

    finbot  -- OWASP FinBot CTF (https://owasp-finbot-ctf.org),
               policy-bypass-fine-print challenge.
"""

# Security policy

Please report vulnerabilities privately through GitHub Security Advisories. Do not include production keys, tokens, signed private payloads, or customer artifacts.

The verifier is deliberately offline and accepts only explicit, workspace-relative regular files. Trust roots are pinned by SHA-256; callers remain responsible for distributing the manifest and public keys through an appropriate trusted channel. A `verified` verdict proves only the checks declared by that manifest and policy.

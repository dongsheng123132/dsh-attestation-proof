# dsh-attestation-proof

Offline, deterministic release-attestation evidence for DeepSeek Harness. It verifies an explicit manifest against a workspace-local subject, pinned public keys, and DSSE-wrapped in-toto statements, then emits a content-addressed JSON verdict.

This fills a narrower gap than `dsh-release-proof` (download byte/version agreement), `dsh-profile-lock-proof` (installed profile contents), or `dsh-audit-bundle` (multi-producer evidence indexing). It does **not** fetch transparency logs, discover trust roots, claim full Sigstore/SLSA conformance, execute build commands, or infer publisher identity.

## What is proved

- subject SHA-256 matches the signed in-toto subject;
- every public key is pinned by SHA-256 and uses Ed25519 or ECDSA P-256/SHA-256;
- a configurable number of distinct trusted signers verifies the DSSE PAE bytes;
- predicate type and hashed JSON-pointer claims meet the explicit policy;
- the JSON verdict is replayable, content-addressed, and verified after write.

The report never contains the signed payload, subject bytes, public-key PEM, secrets, or arbitrary command output. Verification is offline. All filesystem inputs and the artifact directory must stay inside an explicit workspace; symlinks, path traversal, oversized inputs, lifecycle scripts, and overwrites are rejected.

## CLI

```bash
dsh-attestation-proof inspect --workspace . --manifest proof.json
dsh-attestation-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

`verify` exits 0 for `verified`, 2 for a cryptographic/policy rejection, and 1 for invalid or unsafe input. Stdout is one JSON result; errors go to stderr.

## DSH and MCP

The DSH bundle registers `dsh_attestation_proof_inspect` and `dsh_attestation_proof_verify` from one host-neutral core. The independent stdio MCP server exposes proof-only `attestation_proof_inspect` and `attestation_proof_verify`; its inline mode accepts bounded public evidence and performs no filesystem writes.

## Manifest

Schema version 1 requires `subject {id,path,sha256}`, `trust {threshold,keys[]}`, `attestations[]`, and optional `policy {minVerifiedAttestations,allowedPredicateTypes,requiredClaims[]}`. Each key and envelope file carries its own SHA-256 pin. A required claim is `{pointer,sha256}`, where the hash is over canonical JSON for the selected value.

## Development

```bash
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
python C:/Users/ZhuanZ/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

MIT licensed. Security reports: [SECURITY.md](SECURITY.md).

import { inspectAttestationManifestJson, verifyAttestationProof } from './lib/attestation-proof.mjs'

export const name = 'dsh-attestation-proof'
export const inject = ['tools']
export function createDefinitions(config = {}, ctx = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    { name: 'dsh_attestation_proof_inspect', description: 'Inspect an explicit attestation manifest without reading signed evidence.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectAttestationManifestJson(manifestJson) },
    { name: 'dsh_attestation_proof_verify', description: 'Offline verify pinned DSSE/in-toto evidence and write a content-addressed verdict.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async (args) => verifyAttestationProof({ workspaceRoot, ...args }) }
  ]
}
export function apply(ctx, config = {}) { for (const tool of createDefinitions(config, ctx)) ctx.tools.register(tool.name, tool) }

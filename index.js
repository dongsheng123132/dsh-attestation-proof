import { inspectAttestationManifestJson, verifyAttestationProof } from './lib/attestation-proof.mjs'

export const name = 'dsh-attestation-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const withOutput = definition => ({ ...definition, output: { schema: {}, render: renderJson } })
export function createDefinitions(ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    withOutput({ name: 'dsh_attestation_proof_inspect', description: 'Inspect an explicit attestation manifest without reading signed evidence.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectAttestationManifestJson(manifestJson) }),
    withOutput({ name: 'dsh_attestation_proof_verify', description: 'Offline verify pinned DSSE/in-toto evidence and write a content-addressed verdict.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async (args) => verifyAttestationProof({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const tool of createDefinitions(ctx, config)) ctx.tools.register(tool) }

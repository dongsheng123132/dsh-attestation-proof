import { inspectAttestationManifestJson, verifyAttestationInline } from './lib/attestation-proof.mjs'
const VERSION = '0.1.0'; const MAX_LINE = 6 * 1024 * 1024
const tools = [
  { name: 'attestation_proof_inspect', description: 'Inspect an explicit manifest only; no filesystem or network access.', inputSchema: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string', maxLength: 1048576 } }, additionalProperties: false } },
  { name: 'attestation_proof_verify', description: 'Verify bounded inline public evidence; returns no signed payload.', inputSchema: { type: 'object', required: ['manifestJson', 'subjectBase64', 'keysJson', 'envelopesJson'], properties: { manifestJson: { type: 'string', maxLength: 1048576 }, subjectBase64: { type: 'string', maxLength: 1398104 }, keysJson: { type: 'string', maxLength: 2097152 }, envelopesJson: { type: 'string', maxLength: 2097152 } }, additionalProperties: false } }
]
const ok = (id, result) => ({ jsonrpc: '2.0', id, result }); const error = (id, e) => ({ jsonrpc: '2.0', id, error: { code: -32000, message: e.code || 'VERIFICATION_ERROR', data: { code: e.code || 'VERIFICATION_ERROR' } } })
async function dispatch(req) {
  if (req.method === 'initialize') return ok(req.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'dsh-attestation-proof', version: VERSION } })
  if (req.method === 'tools/list') return ok(req.id, { tools })
  if (req.method === 'tools/call') { const value = req.params?.name === 'attestation_proof_inspect' ? inspectAttestationManifestJson(req.params.arguments?.manifestJson) : req.params?.name === 'attestation_proof_verify' ? await verifyAttestationInline(req.params.arguments || {}) : (() => { throw Object.assign(new Error('unknown tool'), { code: 'METHOD_NOT_FOUND' }) })(); return ok(req.id, { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError: false }) }
  return error(req.id, { code: 'METHOD_NOT_FOUND' })
}
let buffer = ''; process.stdin.setEncoding('utf8'); process.stdin.on('data', async chunk => { buffer += chunk; if (buffer.length > MAX_LINE) process.exit(1); let cut; while ((cut = buffer.indexOf('\n')) >= 0) { const line = buffer.slice(0, cut); buffer = buffer.slice(cut + 1); if (!line) continue; let response; try { response = await dispatch(JSON.parse(line)) } catch (e) { response = error(JSON.parse(line).id, e) } process.stdout.write(`${JSON.stringify(response)}\n`) } })

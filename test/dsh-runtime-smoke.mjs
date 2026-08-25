import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { fixture } from './helpers.mjs'

const runtime = process.env.DSH_RUNTIME_ROOT
if (!runtime) throw new Error('DSH_RUNTIME_ROOT must point to an installed @deepseek-ai/dsh directory')
const plugin = process.env.PLUGIN_ENTRY ? await import(pathToFileURL(resolve(process.env.PLUGIN_ENTRY)).href) : await import('../index.js')
const load = relative => import(pathToFileURL(resolve(runtime, 'node_modules/@deepseek-ai', relative, 'lib/index.js')).href)
const { Context } = await load('cordis'); const { default: SystemPrompt } = await load('dsh-system-prompt'); const { default: ToolRuntime } = await load('dsh-tools')
const root = await mkdtemp(join(tmpdir(), 'att-proof-runtime-')); await fixture(root)
const ctx = new Context()
try {
  await ctx.plugin(SystemPrompt); await ctx.plugin(ToolRuntime); await ctx.plugin(plugin, { workspaceRoot: root })
  const tools = ctx.get('tools'); const names = tools.schemas().filter(x => x.name.startsWith('dsh_attestation_proof_')).map(x => x.name); assert.deepEqual(names, ['dsh_attestation_proof_inspect', 'dsh_attestation_proof_verify'])
  const result = await tools.execute({ signal: new AbortController().signal, callId: 'attestation-proof-smoke', name: 'dsh_attestation_proof_verify', arguments: { manifestPath: 'proof.json', artifactDir: 'artifacts' } })
  assert.equal(result.isError, false); assert.equal(result.value.verdict, 'verified'); assert.equal(result.value.artifact.verifiedByReadBack, true); process.stdout.write(`${JSON.stringify({ ok: true, realDshTools: names, verdict: result.value.verdict, artifactSha256: result.value.artifact.sha256 })}\n`)
} finally { await ctx.fiber.dispose(); await rm(root, { recursive: true, force: true }) }

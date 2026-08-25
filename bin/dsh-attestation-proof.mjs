#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { inspectAttestationManifestJson, verifyAttestationProof } from '../lib/attestation-proof.mjs'
const args = process.argv.slice(2); const command = args.shift(); const take = flag => { const i = args.indexOf(flag); return i < 0 ? undefined : args[i + 1] }
try {
  const workspaceRoot = resolve(take('--workspace') || '.'); const manifestPath = take('--manifest')
  if (!manifestPath || !['inspect', 'verify'].includes(command)) throw Object.assign(new Error('usage: dsh-attestation-proof <inspect|verify> --workspace DIR --manifest FILE [--artifactDir DIR]'), { code: 'USAGE' })
  const result = command === 'inspect' ? inspectAttestationManifestJson(await readFile(resolve(workspaceRoot, manifestPath), 'utf8')) : await verifyAttestationProof({ workspaceRoot, manifestPath, artifactDir: take('--artifactDir') })
  process.stdout.write(`${JSON.stringify(result)}\n`); if (result.verdict === 'rejected') process.exitCode = 2
} catch (e) { process.stderr.write(`${JSON.stringify({ ok: false, code: e.code || 'ERROR', message: e.message })}\n`); process.exitCode = 1 }

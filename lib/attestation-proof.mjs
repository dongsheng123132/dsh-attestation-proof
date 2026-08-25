import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const sha = (value) => createHash('sha256').update(value).digest('hex')
const stable = (value) => JSON.stringify(value, (_, v) => v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v)
const fail = (code, message) => Object.assign(new Error(message), { code })
const assertString = (value, label, max = 512) => { if (typeof value !== 'string' || !value || value.length > max) throw fail('INVALID_MANIFEST', `${label} must be a non-empty bounded string`) }
const assertHash = (value, label) => { if (!HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const containsSecretField = (value) => value && typeof value === 'object' && Object.entries(value).some(([key, child]) => /(?:secret|password|credential|api[_-]?key|private[_-]?key|token)$/i.test(key) || containsSecretField(child))

async function safeFile(root, path, expectedHash) {
  assertString(path, 'path'); if (isAbsolute(path)) throw fail('PATH_ESCAPE', 'paths must be workspace-relative')
  const absolute = resolve(root, path); const rel = relative(root, absolute)
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'path escapes workspaceRoot')
  let stat; try { stat = await lstat(absolute) } catch { throw fail('MISSING_EVIDENCE', `missing evidence: ${path}`) }
  if (stat.isSymbolicLink() || !stat.isFile()) throw fail('UNSAFE_FILE', 'evidence must be a regular non-symlink file')
  if (stat.size > MAX_FILE) throw fail('FILE_TOO_LARGE', 'evidence exceeds 1 MiB')
  const real = await realpath(absolute); if (relative(await realpath(root), real).startsWith('..')) throw fail('PATH_ESCAPE', 'real path escapes workspaceRoot')
  const bytes = await readFile(real); if (expectedHash && sha(bytes) !== expectedHash) throw fail('DIGEST_MISMATCH', `digest mismatch: ${path}`)
  return bytes
}

function parseManifest(input) {
  const m = typeof input === 'string' ? JSON.parse(input) : input
  if (!m || m.schemaVersion !== 1 || containsSecretField(m)) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required and secret-shaped fields are forbidden')
  assertString(m.subject?.id, 'subject.id'); assertHash(m.subject?.sha256, 'subject.sha256'); assertString(m.subject?.path, 'subject.path')
  if (!Number.isInteger(m.trust?.threshold) || m.trust.threshold < 1) throw fail('INVALID_MANIFEST', 'positive trust.threshold required')
  if (!Array.isArray(m.trust.keys) || m.trust.keys.length < m.trust.threshold || m.trust.keys.length > 32) throw fail('INVALID_MANIFEST', 'trust.keys must satisfy threshold and limit')
  if (!Array.isArray(m.attestations) || !m.attestations.length || m.attestations.length > 64) throw fail('INVALID_MANIFEST', '1..64 attestations required')
  const ids = new Set(); for (const key of m.trust.keys) { assertString(key.id, 'key.id'); if (ids.has(key.id)) throw fail('INVALID_MANIFEST', 'duplicate key id'); ids.add(key.id); if (!['ed25519', 'ecdsa-p256-sha256'].includes(key.algorithm)) throw fail('INVALID_MANIFEST', 'unsupported key algorithm'); assertString(key.publicKeyPath, 'key.publicKeyPath'); assertHash(key.sha256, 'key.sha256') }
  for (const a of m.attestations) { assertString(a.id, 'attestation.id'); assertString(a.path, 'attestation.path'); assertHash(a.sha256, 'attestation.sha256') }
  return m
}

function pae(type, payload) { return Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]) }
function jsonPointer(value, pointer) { if (pointer === '') return value; if (!pointer.startsWith('/')) return undefined; return pointer.slice(1).split('/').reduce((v, p) => v?.[p.replace(/~1/g, '/').replace(/~0/g, '~')], value) }

export function inspectAttestationManifestJson(manifestJson) {
  const m = parseManifest(manifestJson)
  return { schemaVersion: 1, subjectId: m.subject.id, threshold: m.trust.threshold, keyCount: m.trust.keys.length, attestationCount: m.attestations.length, filesystemAccess: false, returnsSignedPayloads: false }
}

async function evaluate(m, subjectBytes, keyBytes, envelopeBytes) {
  const subjectDigest = sha(subjectBytes); const keys = new Map(); const keyResults = []
  for (let i = 0; i < m.trust.keys.length; i++) { const spec = m.trust.keys[i]; const pem = keyBytes[i]; let key; try { key = createPublicKey(pem) } catch { throw fail('INVALID_KEY', `invalid public key: ${spec.id}`) }; keys.set(spec.id, { spec, key }); keyResults.push({ id: spec.id, algorithm: spec.algorithm, sha256: sha(pem), trusted: sha(pem) === spec.sha256 }) }
  const attestations = []; const verifiedSigners = new Set()
  for (let i = 0; i < m.attestations.length; i++) {
    const spec = m.attestations[i]; let envelope; try { envelope = JSON.parse(envelopeBytes[i]) } catch { throw fail('INVALID_ENVELOPE', `invalid envelope: ${spec.id}`) }
    assertString(envelope.payloadType, 'payloadType'); if (!Array.isArray(envelope.signatures) || typeof envelope.payload !== 'string') throw fail('INVALID_ENVELOPE', 'DSSE payload and signatures required')
    const payload = Buffer.from(envelope.payload, 'base64'); if (payload.length > MAX_FILE) throw fail('FILE_TOO_LARGE', 'payload exceeds 1 MiB')
    let statement; try { statement = JSON.parse(payload) } catch { throw fail('INVALID_ENVELOPE', 'payload must be JSON') }
    const signers = []
    for (const sig of envelope.signatures) { const trusted = keys.get(sig.keyid); if (!trusted || !trusted.spec || !keyResults.find(k => k.id === sig.keyid)?.trusted) continue; let ok = false; try { ok = cryptoVerify(trusted.spec.algorithm === 'ed25519' ? null : 'sha256', pae(envelope.payloadType, payload), trusted.key, Buffer.from(sig.sig, 'base64')) } catch {} if (ok) { verifiedSigners.add(sig.keyid); signers.push(sig.keyid) } }
    const subjectMatch = Array.isArray(statement.subject) && statement.subject.some(s => s.name === m.subject.id && s.digest?.sha256 === m.subject.sha256)
    const predicateAllowed = !m.policy?.allowedPredicateTypes?.length || m.policy.allowedPredicateTypes.includes(statement.predicateType)
    const claims = (m.policy?.requiredClaims || []).map(c => ({ pointer: c.pointer, expectedSha256: c.sha256, actualSha256: sha(stable(jsonPointer(statement, c.pointer))), matched: sha(stable(jsonPointer(statement, c.pointer))) === c.sha256 }))
    attestations.push({ id: spec.id, sha256: sha(envelopeBytes[i]), predicateType: statement.predicateType || null, verifiedSigners: [...new Set(signers)].sort(), subjectMatch, predicateAllowed, claims })
  }
  const thresholdMet = verifiedSigners.size >= m.trust.threshold
  const subjectDigestMatch = subjectDigest === m.subject.sha256
  const validAttestations = attestations.filter(a => a.verifiedSigners.length && a.subjectMatch && a.predicateAllowed && a.claims.every(c => c.matched)).length
  const min = m.policy?.minVerifiedAttestations ?? 1
  const verdict = subjectDigestMatch && thresholdMet && keyResults.every(k => k.trusted) && validAttestations >= min ? 'verified' : 'rejected'
  return { schemaVersion: 1, verdict, subject: { id: m.subject.id, sha256: subjectDigest, digestMatched: subjectDigestMatch }, policy: { threshold: m.trust.threshold, distinctVerifiedSigners: [...verifiedSigners].sort(), thresholdMet, minVerifiedAttestations: min, validAttestations }, keys: keyResults, attestations, returnsSignedPayloads: false, networkAccess: false }
}

export async function verifyAttestationProof({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const manifestBytes = await safeFile(root, manifestPath); const m = parseManifest(manifestBytes.toString('utf8'))
  const subject = await safeFile(root, m.subject.path); const keyBytes = await Promise.all(m.trust.keys.map(k => safeFile(root, k.publicKeyPath, k.sha256))); const envelopes = await Promise.all(m.attestations.map(a => safeFile(root, a.path, a.sha256)))
  const report = await evaluate(m, subject, keyBytes, envelopes); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha(bytes)
  if (!artifactDir || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  await mkdir(dir, { recursive: true }); const out = resolve(dir, `attestation-proof-${digest}.json`)
  try { await writeFile(out, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; const old = await readFile(out); if (!old.equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(out); if (sha(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back verification failed')
  return { ...report, artifact: { path: relative(root, out).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}

export async function verifyAttestationInline({ manifestJson, subjectBase64, keysJson, envelopesJson }) {
  const m = parseManifest(manifestJson); const keys = typeof keysJson === 'string' ? JSON.parse(keysJson) : keysJson; const envs = typeof envelopesJson === 'string' ? JSON.parse(envelopesJson) : envelopesJson
  if (!Array.isArray(keys) || !Array.isArray(envs) || containsSecretField(keys) || containsSecretField(envs)) throw fail('FORBIDDEN_FIELD', 'bounded public keys and envelopes arrays required; secret-shaped fields are forbidden')
  const keyBytes = m.trust.keys.map(k => { const found = keys.find(x => x.id === k.id); if (!found?.pem) throw fail('MISSING_EVIDENCE', `missing public key: ${k.id}`); return Buffer.from(found.pem) })
  const envelopeBytes = m.attestations.map(a => { const found = envs.find(x => x.id === a.id); if (!found?.envelope) throw fail('MISSING_EVIDENCE', `missing envelope: ${a.id}`); return Buffer.from(stable(found.envelope)) })
  return evaluate(m, Buffer.from(subjectBase64, 'base64'), keyBytes, envelopeBytes)
}

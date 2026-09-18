#!/usr/bin/env node
/**
 * attest.mjs — build the manifest the attestation workflow signs, and record the result.
 *
 *   node scripts/sentinel/attest.mjs manifest <out.json>
 *       Verifies every ledger under research/sentinel/ledger/, writes a manifest of their chain
 *       heads, and prints `changed=true|false` (against the newest attestation) for the workflow.
 *
 *   node scripts/sentinel/attest.mjs finalize <manifest.json> <bundle.json> [<tsa.txt>] <outdir>
 *       Reads the Sigstore bundle (Rekor log index and integrated time) and, if present, the text
 *       of an RFC 3161 timestamp reply, and writes <outdir>/<utc>-<commit>.json next to copies of
 *       the bundle and the reply. Node built-ins only.
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha256, verify } from './ledger.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')
const LEDGER_DIR = path.join(ROOT, 'research', 'sentinel', 'ledger')
const ATTEST_DIR = path.join(ROOT, 'research', 'sentinel', 'attestations')

function head() {
  try {
    return process.env.GITHUB_SHA || execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
  } catch {
    return null
  }
}

function newestAttestation() {
  if (!existsSync(ATTEST_DIR)) return null
  const files = readdirSync(ATTEST_DIR).filter((f) => /^\d{4}-\d{2}-\d{2}T.*\.json$/.test(f) && !f.endsWith('.sigstore.json')).sort()
  if (!files.length) return null
  try {
    return JSON.parse(readFileSync(path.join(ATTEST_DIR, files[files.length - 1]), 'utf8'))
  } catch {
    return null
  }
}

function manifest(out) {
  const files = existsSync(LEDGER_DIR) ? readdirSync(LEDGER_DIR).filter((f) => f.endsWith('.jsonl')).sort() : []
  const entries = files.map((f) => {
    const p = path.join(LEDGER_DIR, f)
    const v = verify(p)
    return { path: `research/sentinel/ledger/${f}`, sha256: sha256(readFileSync(p)), lines: v.lines, head: v.head, chain_ok: v.ok, broken_at: v.brokenAt }
  })
  const m = { v: 1, kind: 'vigilia-sentinel-ledger-manifest', ts: new Date().toISOString(), repo: process.env.GITHUB_REPOSITORY || 'GvHildebrand/vigilia', commit: head(), files: entries }
  writeFileSync(out, JSON.stringify(m, null, 2) + '\n')
  const prev = newestAttestation()
  const prevHeads = JSON.stringify((prev?.manifest?.files ?? []).map((f) => [f.path, f.head]))
  const nowHeads = JSON.stringify(entries.map((f) => [f.path, f.head]))
  const changed = prevHeads !== nowHeads
  const line = `changed=${changed}\nledgers=${entries.length}\n`
  if (process.env.GITHUB_OUTPUT) writeFileSync(process.env.GITHUB_OUTPUT, line, { flag: 'a' })
  process.stdout.write(line)
}

function rekorFromBundle(b) {
  // New bundle format (protobuf JSON) and the older cosign format both appear in the wild.
  const t = b?.verificationMaterial?.tlogEntries?.[0]
  if (t) return { logIndex: Number(t.logIndex), integratedTime: Number(t.integratedTime), logId: t.logId?.keyId ?? null, format: 'sigstore-bundle' }
  const r = b?.rekorBundle?.Payload
  if (r) return { logIndex: Number(r.logIndex), integratedTime: Number(r.integratedTime), logId: r.logID ?? null, format: 'cosign-bundle' }
  return { logIndex: null, integratedTime: null, logId: null, format: 'unknown' }
}

function tsaFromText(text) {
  if (!text) return null
  const gen = text.match(/Time stamp:\s*(.+)/)?.[1]?.trim() ?? null
  const serial = text.match(/Serial number:\s*(.+)/)?.[1]?.trim() ?? null
  const tsa = text.match(/TSA:\s*(.+)/)?.[1]?.trim() ?? null
  const policy = text.match(/Policy OID:\s*(.+)/)?.[1]?.trim() ?? null
  return { generated: gen, serial, tsa, policy }
}

function finalize(manifestPath, bundlePath, tsaTextPath, outDir) {
  const m = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const b = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const rekor = rekorFromBundle(b)
  const tsa = tsaTextPath && existsSync(tsaTextPath) ? tsaFromText(readFileSync(tsaTextPath, 'utf8')) : null
  mkdirSync(outDir, { recursive: true })
  const stamp = m.ts.replace(/[:.]/g, '-').replace(/-\d{3}Z$/, 'Z')
  const base = `${stamp}-${(m.commit || 'nocommit').slice(0, 7)}`
  copyFileSync(bundlePath, path.join(outDir, `${base}.sigstore.json`))
  if (tsa && tsaTextPath) {
    const tsr = tsaTextPath.replace(/\.txt$/, '.tsr')
    if (existsSync(tsr)) copyFileSync(tsr, path.join(outDir, `${base}.tsr`))
  }
  const rec = {
    v: 1,
    kind: 'vigilia-sentinel-attestation',
    manifest: m,
    manifest_sha256: sha256(readFileSync(manifestPath)),
    rekor: { ...rekor, integratedTimeISO: rekor.integratedTime ? new Date(rekor.integratedTime * 1000).toISOString() : null, search: rekor.logIndex != null ? `https://search.sigstore.dev/?logIndex=${rekor.logIndex}` : null },
    tsa,
    bundle: `${base}.sigstore.json`,
    tsr: tsa ? `${base}.tsr` : null,
    verify: {
      // The identity is the repository whose workflow sealed this; a reader of a copy elsewhere
      // still verifies against the sealing repository, never the copy's.
      cosign: `cosign verify-blob ${base}.manifest.json --bundle ${base}.sigstore.json --certificate-identity-regexp '^https://github.com/${m.repo}/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`,
      openssl: tsa ? `openssl ts -verify -data ${base}.manifest.json -in ${base}.tsr -CAfile digicert-tsa-chain.pem   # chain: docs/verify.md` : null,
      sealed_by: `https://github.com/${m.repo}`,
    },
  }
  writeFileSync(path.join(outDir, `${base}.json`), JSON.stringify(rec, null, 2) + '\n')
  copyFileSync(manifestPath, path.join(outDir, `${base}.manifest.json`))
  const summary = `attested ${m.files.length} ledger(s) at ${m.commit?.slice(0, 7) ?? '?'}: rekor index ${rekor.logIndex ?? '?'}${tsa?.generated ? `, TSA ${tsa.generated}` : ''}`
  if (process.env.GITHUB_OUTPUT) writeFileSync(process.env.GITHUB_OUTPUT, `summary=${summary}\nfile=${base}.json\n`, { flag: 'a' })
  process.stdout.write(summary + '\n')
}

const [cmd, ...args] = process.argv.slice(2)
if (cmd === 'manifest') manifest(args[0] || path.join(ROOT, 'manifest.json'))
else if (cmd === 'finalize') {
  if (args.length === 3) finalize(args[0], args[1], null, args[2])
  else finalize(args[0], args[1], args[2], args[3])
} else {
  console.error('usage: attest.mjs manifest <out.json> | finalize <manifest.json> <bundle.json> [<tsa.txt>] <outdir>')
  process.exit(1)
}

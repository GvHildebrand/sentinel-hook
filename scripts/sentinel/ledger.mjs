/**
 * ledger.mjs — an append-only, hash-chained record.
 *
 * One JSONL file per identity. Every line carries `prev` (the previous line's hash) and `hash`
 * (sha256 of the canonical JSON of the line without `hash`). Editing or deleting any line breaks
 * every hash after it, which `verify()` reports. The chain head is what the attestation workflow
 * seals into the Sigstore transparency log, so a reader can check that the record they hold is the
 * one that existed when it was sealed.
 *
 * This file is written by the sentinel, which is a script, not by the agent it watches. That is
 * the point: a record of a control firing, written by something that is not the claimant.
 */

import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import path from 'node:path'

/** Canonical JSON: sorted keys, no whitespace, undefined-valued keys omitted (JSON.stringify drops them too, so the written line and the hashed body must agree). */
export function canonical(obj) {
  if (Array.isArray(obj)) return '[' + obj.map((x) => (x === undefined ? 'null' : canonical(x))).join(',') + ']'
  if (obj && typeof obj === 'object') {
    return '{' + Object.keys(obj).filter((k) => obj[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}'
  }
  return JSON.stringify(obj)
}

export function sha256(s) {
  return createHash('sha256').update(s).digest('hex')
}

export function lastHash(file) {
  if (!existsSync(file)) return null
  const text = readFileSync(file, 'utf8')
  let i = text.length - 1
  while (i >= 0 && (text[i] === '\n' || text[i] === '\r')) i--
  if (i < 0) return null
  const start = text.lastIndexOf('\n', i) + 1
  try {
    return JSON.parse(text.slice(start, i + 1)).hash ?? null
  } catch {
    return null
  }
}

/** Append `record` to `file`, chaining it to the previous line. Returns the completed record. */
export function append(file, record) {
  mkdirSync(path.dirname(file), { recursive: true })
  const prev = lastHash(file)
  const body = { ...record, prev }
  delete body.hash
  const hash = sha256(canonical(body))
  const full = { ...body, hash }
  appendFileSync(file, JSON.stringify(full) + '\n')
  return full
}

/** Verify a ledger file. Returns { ok, lines, head, brokenAt } — brokenAt is the 1-based line. */
export function verify(file) {
  // A ledger that does not exist is not an intact ledger. (Stranger test 1, confusion 8.)
  if (!existsSync(file)) return { ok: false, lines: 0, head: null, brokenAt: null, why: 'missing' }
  const text = readFileSync(file, 'utf8')
  const lines = text.split('\n').filter((l) => l.trim())
  let prev = null
  for (let i = 0; i < lines.length; i++) {
    let rec
    try {
      rec = JSON.parse(lines[i])
    } catch {
      return { ok: false, lines: lines.length, head: prev, brokenAt: i + 1, why: 'unparseable' }
    }
    const { hash, ...body } = rec
    if (body.prev !== prev) return { ok: false, lines: lines.length, head: prev, brokenAt: i + 1, why: 'prev mismatch' }
    if (sha256(canonical(body)) !== hash) return { ok: false, lines: lines.length, head: prev, brokenAt: i + 1, why: 'hash mismatch' }
    prev = hash
  }
  return { ok: true, lines: lines.length, head: prev, brokenAt: null }
}

const SECRET_RX = /((?:api[_-]?key|token|secret|password|passwd|authorization|bearer|x-api-key|sk-ant-|ghp_|gho_|AKIA)[=:\s"']*)[A-Za-z0-9._\-+/=]{8,}/gi

/** A bounded, redacted excerpt for the record. Never the full command. */
export function excerpt(s, max = 160) {
  const red = String(s).replace(SECRET_RX, '$1[REDACTED]').replace(/\s+/g, ' ').trim()
  return red.length > max ? red.slice(0, max) + '…' : red
}

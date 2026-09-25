/**
 * ledger.mjs — an append-only, hash-chained record.
 *
 * One JSONL file per chain. Every line carries `prev` (the previous line's hash) and `hash`
 * (sha256 of the canonical JSON of the line without `hash`). Editing or deleting any line breaks
 * every hash after it, which `verify()` reports. The chain head is what gets sealed — into the
 * Sigstore transparency log by the attestation workflow, or to the witness by the flusher — so a
 * reader can check that the record they hold is the one that existed when it was sealed.
 *
 * This file is written by the hook, which is a script, not by the agent it watches. That is the
 * point: a record of a control firing, written by something that is not the claimant.
 *
 * Concurrency (0.4.0). Parallel sessions and subagents append to the same file at the same time.
 * Reading the last hash and then writing is a race: two writers can read the same head and fork the
 * chain. `append()` therefore takes a lock file (`<file>.lock`, created with O_EXCL), spins briefly
 * with jitter, and removes a lock older than a few seconds as stale (a hook killed mid-append). If
 * the lock still cannot be had within about a second, it appends anyway and says so in the line
 * (`lock: false`): losing the entry or stalling the agent would be worse than a visible fork.
 *
 * Only the tail of the file is read on append, so a ledger that grows for months stays cheap to
 * extend. Node built-ins only, so a lockfile drift can never disable it.
 */

import { createHash } from 'node:crypto'
import { appendFileSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, statSync, unlinkSync } from 'node:fs'
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

/** The last complete line of a file, parsed, read from the tail only. null if none or unparseable. */
export function lastRecord(file) {
  if (!existsSync(file)) return null
  let fd
  try {
    fd = openSync(file, 'r')
    const size = fstatSync(fd).size
    if (size === 0) return null
    // A line is a few hundred bytes; read a growing window from the end until one whole line fits.
    for (let win = 16384; ; win *= 4) {
      const len = Math.min(win, size)
      const buf = Buffer.alloc(len)
      readSync(fd, buf, 0, len, size - len)
      const text = buf.toString('utf8')
      let i = text.length - 1
      while (i >= 0 && (text[i] === '\n' || text[i] === '\r')) i--
      if (i < 0) return null
      const nl = text.lastIndexOf('\n', i)
      if (nl === -1 && len < size) continue // the last line is longer than the window
      try {
        return JSON.parse(text.slice(nl + 1, i + 1))
      } catch {
        return null
      }
    }
  } catch {
    return null
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

export function lastHash(file) {
  return lastRecord(file)?.hash ?? null
}

function countLines(file) {
  if (!existsSync(file)) return 0
  return readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).length
}

const SLEEP = new Int32Array(new SharedArrayBuffer(4))
function sleepMs(ms) {
  Atomics.wait(SLEEP, 0, 0, ms)
}

/**
 * Take `<file>.lock`. Returns a release function, or null if the lock could not be taken within
 * `waitMs`. A lock older than `staleMs` belongs to a writer that died; it is removed.
 */
export function acquireLock(file, { waitMs = 1000, staleMs = 5000 } = {}) {
  const lock = file + '.lock'
  const deadline = Date.now() + waitMs
  for (;;) {
    try {
      const fd = openSync(lock, 'wx')
      closeSync(fd)
      return () => {
        try {
          unlinkSync(lock)
        } catch {
          /* already gone */
        }
      }
    } catch (err) {
      if (err?.code !== 'EEXIST') return null
      try {
        if (Date.now() - statSync(lock).mtimeMs > staleMs) {
          unlinkSync(lock)
          continue
        }
      } catch {
        continue // removed between our open and our stat: try again at once
      }
    }
    if (Date.now() >= deadline) return null
    sleepMs(2 + Math.floor(Math.random() * 8))
  }
}

/**
 * Append `record` to `file`, chaining it to the previous line. Returns the completed record.
 *
 * With `{ seq: true }` the line also carries `seq`, its 1-based position in the chain, which is
 * what a seal reports as the number of actions witnessed and what makes a gap visible.
 */
export function append(file, record, { seq = false, waitMs, staleMs } = {}) {
  mkdirSync(path.dirname(file), { recursive: true })
  const release = acquireLock(file, { waitMs, staleMs })
  try {
    const last = lastRecord(file)
    const prev = last?.hash ?? null
    const body = { ...record }
    delete body.hash
    delete body.prev
    if (seq) body.seq = last == null ? (existsSync(file) ? countLines(file) + 1 : 1) : Number.isInteger(last.seq) ? last.seq + 1 : countLines(file) + 1
    if (!release) body.lock = false
    body.prev = prev
    const hash = sha256(canonical(body))
    const full = { ...body, hash }
    appendFileSync(file, JSON.stringify(full) + '\n')
    return full
  } finally {
    if (release) release()
  }
}

/**
 * Verify a ledger file. Returns { ok, lines, head, brokenAt } — brokenAt is the 1-based line.
 * A line that carries `seq` must carry its own position: a gap or a repeat is a broken chain.
 */
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
    if (body.seq !== undefined && body.seq !== i + 1) return { ok: false, lines: lines.length, head: prev, brokenAt: i + 1, why: 'seq mismatch' }
    prev = hash
  }
  return { ok: true, lines: lines.length, head: prev, brokenAt: null }
}

/** The hash of every line, in order (for checking a sealed head against the chain). */
export function lineHashes(file) {
  if (!existsSync(file)) return []
  const out = []
  for (const l of readFileSync(file, 'utf8').split('\n')) {
    if (!l.trim()) continue
    try {
      out.push(JSON.parse(l).hash ?? null)
    } catch {
      out.push(null)
    }
  }
  return out
}

const SECRET_RX = /((?:api[_-]?key|token|secret|password|passwd|authorization|bearer|x-api-key|sk-ant-|ghp_|gho_|AKIA)[=:\s"']*)[A-Za-z0-9._\-+/=]{8,}/gi

/** A bounded, redacted excerpt for the record. Never the full command. */
export function excerpt(s, max = 160) {
  const red = String(s).replace(SECRET_RX, '$1[REDACTED]').replace(/\s+/g, ' ').trim()
  return red.length > max ? red.slice(0, max) + '…' : red
}

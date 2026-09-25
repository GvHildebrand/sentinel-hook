/**
 * witness-client.mjs — the only code that talks to the witness.
 *
 * The privacy boundary lives here, and it is small on purpose. Exactly two messages ever leave
 * the machine, and both are built field by field below — nothing is spread from a hook input:
 *
 *   seal       { v: 1, pub, head, seq, ts, sig }
 *              `head` is the hash of the latest ledger line. It is not a hash of a command: a plain
 *              sha256 of `git push --force` could be guessed by hashing candidates; a line carries a
 *              random 16-byte nonce, so its hash cannot. `seq` is the number of lines in the chain,
 *              which is what makes a gap or a rewrite visible to the witness.
 *   near-miss  { v: 1, pub, category, entry?, ts, sig }   (opt-in only)
 *              `category` is one of five words; `entry` is the hash of the local line it refers to.
 *              No free text, ever.
 *
 * HTTP: POST JSON with `content-type` and `user-agent: sentinel-hook/<version>`, nothing else — no
 * cookies, no identifiers — and a short timeout. Redirects are not followed.
 *
 * Sealing is asynchronous and fails open. The hook only appends locally; `flush()` runs in a
 * detached process, sends the latest head (which commits to every earlier line), keeps the
 * witness's signed receipt, and backs off on failure. A witness that is down blocks nothing: the
 * head is sealed later, and the seal still commits to everything before it.
 */

import http from 'node:http'
import https from 'node:https'
import { appendFileSync, existsSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { canonical, lastRecord, sha256 } from './ledger.mjs'
import { VERSION, ensureDir, paths, readConfig, readState, witnessEnabled, writeState } from './home.mjs'
import { ensureKey, signMessage, verifyString } from './keys.mjs'

export const CATEGORIES = ['destructive_command', 'credential_exposure', 'unreviewed_push', 'injection_suspected', 'other']
export const SEAL_KEYS = ['v', 'pub', 'head', 'seq', 'ts', 'sig']
export const NEAR_MISS_KEYS = ['v', 'pub', 'category', 'entry', 'ts', 'sig']
const HEX64 = /^[0-9a-f]{64}$/
const TIMEOUT_MS = 5000
const BACKOFF_BASE_MS = 60_000
const BACKOFF_MAX_MS = 6 * 3600_000

/**
 * The coarse category a gate decision is reported under, when the user has opted in to sharing
 * near-misses. Mapped from the rule id alone; the command is consulted only to tell a push from a
 * local history rewrite under B07, and never leaves the machine.
 */
export function categoryForRule(ruleId, command = '') {
  const id = String(ruleId || '').split('.')[0]
  if (['B01', 'B02', 'B03', 'B04', 'B05', 'B06', 'B08', 'B09', 'B12'].includes(id)) return 'destructive_command'
  if (id === 'B07') return /(^|[\s;&|(])git\s+push\b/.test(String(command)) ? 'unreviewed_push' : 'destructive_command'
  if (['B13', 'B14', 'R01', 'W03'].includes(id)) return 'credential_exposure'
  if (['B10', 'B11', 'B17', 'W06'].includes(id)) return 'injection_suspected'
  return 'other'
}

export function buildSeal(key, { head, seq, ts = new Date().toISOString() }) {
  const msg = { v: 1, pub: key.pub, head: String(head), seq: Number(seq), ts }
  return { ...msg, sig: signMessage(key.privateKey, msg) }
}

export function buildNearMiss(key, { category, entry, ts = new Date().toISOString() }) {
  if (!CATEGORIES.includes(category)) throw new Error(`category must be one of ${CATEGORIES.join(', ')}`)
  if (entry != null && !HEX64.test(String(entry))) throw new Error('entry must be a 64-character sha256 hex (a ledger line hash)')
  const msg = { v: 1, pub: key.pub, category, ts }
  if (entry != null) msg.entry = String(entry)
  return { ...msg, sig: signMessage(key.privateKey, msg) }
}

/** POST a JSON body. Resolves { status, json } or rejects on network error / timeout. */
export function postJson(url, body, { timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let u
    try {
      u = new URL(url)
    } catch (err) {
      reject(err)
      return
    }
    const lib = u.protocol === 'https:' ? https : u.protocol === 'http:' ? http : null
    if (!lib) {
      reject(new Error(`unsupported protocol ${u.protocol}`))
      return
    }
    const data = Buffer.from(JSON.stringify(body))
    const req = lib.request(
      u,
      {
        method: 'POST',
        agent: false,
        timeout: timeoutMs,
        headers: { 'content-type': 'application/json', 'user-agent': `sentinel-hook/${VERSION}`, 'content-length': data.length },
      },
      (res) => {
        const chunks = []
        let size = 0
        res.on('data', (c) => {
          size += c.length
          if (size <= 65536) chunks.push(c)
        })
        res.on('end', () => {
          let json = null
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          } catch {
            /* not JSON */
          }
          resolve({ status: res.statusCode, json, retryAfter: Number(res.headers['retry-after']) || null })
        })
        res.on('error', reject)
      },
    )
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end(data)
  })
}

function endpoint(cfg, p) {
  return String(cfg.witness_url).replace(/\/+$/, '') + p
}

/**
 * Check a receipt against the seal it answers: the leaf is the hash of the seal we sent, the
 * entry hash is the hash of { i, t, leaf, prev }, and the server signed that hash.
 */
export function checkReceipt(seal, receipt) {
  if (!receipt || typeof receipt !== 'object') return { ok: false, why: 'no receipt' }
  if (receipt.leaf !== sha256(canonical(seal))) return { ok: false, why: 'leaf does not match the seal' }
  const { i, t, leaf, prev } = receipt
  if (receipt.hash !== sha256(canonical({ i, t, leaf, prev }))) return { ok: false, why: 'entry hash does not match' }
  if (!verifyString(receipt.server_pub, receipt.hash, receipt.server_sig)) return { ok: false, why: 'server signature invalid' }
  return { ok: true }
}

function backoffMs(failures) {
  return Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1), BACKOFF_MAX_MS)
}

function takeFlushLock(file) {
  try {
    writeFileSync(file, String(process.pid), { flag: 'wx' })
    return () => {
      try {
        unlinkSync(file)
      } catch {
        /* gone */
      }
    }
  } catch {
    try {
      if (Date.now() - statSync(file).mtimeMs > 30_000) {
        unlinkSync(file)
        return takeFlushLock(file)
      }
    } catch {
      /* raced */
    }
    return null
  }
}

/**
 * Seal the latest head, if there is anything new. Never throws; returns what happened.
 *   { status: 'off' | 'no-ledger' | 'nothing-new' | 'backoff' | 'busy' | 'sealed' | 'failed', ... }
 */
export async function flush({ env = process.env, force = false } = {}) {
  const p = paths(env)
  const cfg = readConfig(env)
  if (!witnessEnabled(cfg, env)) return { status: 'off' }
  const release = takeFlushLock(p.flushLock)
  if (!release) return { status: 'busy' }
  try {
    const state = readState(env)
    const now = Date.now()
    if (!force && state.next_attempt_at && now < Date.parse(state.next_attempt_at)) return { status: 'backoff', next: state.next_attempt_at }
    const last = lastRecord(p.ledger)
    const result = { status: 'nothing-new' }
    if (!last?.hash) result.status = 'no-ledger'
    else if (!(state.last_sealed && state.last_sealed.head === last.hash)) {
      const key = ensureKey(p.key)
      const seq = Number.isInteger(last.seq) ? last.seq : null
      if (seq == null) {
        result.status = 'failed'
        result.error = 'ledger line has no seq'
      } else {
        state.last_attempt_at = new Date(now).toISOString()
        const seal = buildSeal(key, { head: last.hash, seq })
        try {
          const res = await postJson(endpoint(cfg, '/v1/seal'), seal)
          if (res.status === 429) {
            // Rate-limited is not a failure: the witness is up and will take this head in a moment.
            state.next_attempt_at = new Date(now + Math.min(3600, Math.max(1, res.retryAfter || 10)) * 1000).toISOString()
            writeState(state, env)
            return { status: 'rate-limited', next: state.next_attempt_at }
          }
          if (res.status !== 200 || !res.json?.receipt) throw new Error(`witness answered ${res.status}${res.json?.error ? ': ' + String(res.json.error).slice(0, 80) : ''}`)
          const receipt = res.json.receipt
          const check = checkReceipt(seal, receipt)
          if (!check.ok) throw new Error(`receipt rejected: ${check.why}`)
          const keyChanged = Boolean(state.server_pub && state.server_pub !== receipt.server_pub)
          ensureDir(p.root, 0o700)
          appendFileSync(p.receipts, JSON.stringify({ seal, receipt, flags: res.json.flags || undefined, server_key_changed: keyChanged || undefined, received_at: new Date().toISOString() }) + '\n', { mode: 0o600 })
          state.server_pub ??= receipt.server_pub
          if (keyChanged) state.server_key_changed = true
          state.last_sealed = { head: last.hash, seq, at: receipt.t, i: receipt.i }
          state.failures = 0
          delete state.next_attempt_at
          delete state.last_error
          result.status = 'sealed'
          result.receipt = receipt
          result.seq = seq
        } catch (err) {
          state.failures = (state.failures || 0) + 1
          state.next_attempt_at = new Date(now + backoffMs(state.failures)).toISOString()
          state.last_error = String(err?.message || err).slice(0, 160)
          result.status = 'failed'
          result.error = state.last_error
        }
        writeState(state, env)
      }
    }
    // Near-misses that could not be sent at the time are retried here, re-signed with a fresh ts.
    if (result.status !== 'failed') await sendPendingNearMisses({ env, cfg })
    return result
  } finally {
    release()
  }
}

/** Send one near-miss now. Returns { ok, status?, error? }. */
export async function sendNearMiss({ env = process.env, category, entry } = {}) {
  const cfg = readConfig(env)
  if (!witnessEnabled(cfg, env)) return { ok: false, error: 'witness is off (offline install, witness: false, or VIGILIA_WITNESS=off)' }
  const key = ensureKey(paths(env).key)
  const msg = buildNearMiss(key, { category, entry })
  try {
    const res = await postJson(endpoint(cfg, '/v1/near-miss'), msg)
    if (res.status !== 200) return { ok: false, status: res.status, error: res.json?.error || `witness answered ${res.status}` }
    return { ok: true, status: 200, counted: res.json?.counted }
  } catch (err) {
    return { ok: false, error: String(err?.message || err).slice(0, 160) }
  }
}

/** Queue a near-miss locally for a later retry (only the category and the entry hash are kept). */
export function queueNearMiss({ env = process.env, category, entry }) {
  const p = paths(env)
  ensureDir(p.root, 0o700)
  appendFileSync(p.pendingNearMiss, JSON.stringify({ category, entry: entry ?? undefined }) + '\n', { mode: 0o600 })
}

async function sendPendingNearMisses({ env, cfg }) {
  const p = paths(env)
  if (!existsSync(p.pendingNearMiss) || !cfg?.share_near_misses) return
  const items = readFileSync(p.pendingNearMiss, 'utf8').split('\n').filter(Boolean).map((l) => {
    try {
      return JSON.parse(l)
    } catch {
      return null
    }
  }).filter(Boolean)
  const keep = []
  for (const it of items) {
    if (!CATEGORIES.includes(it.category)) continue
    const r = await sendNearMiss({ env, category: it.category, entry: it.entry })
    if (!r.ok && !(r.status >= 400 && r.status < 500 && r.status !== 429)) keep.push(it)
  }
  writeFileSync(p.pendingNearMiss, keep.map((x) => JSON.stringify(x) + '\n').join(''), { mode: 0o600 })
}

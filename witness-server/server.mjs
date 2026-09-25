#!/usr/bin/env node
/**
 * witness-server — Vigilia's witness. One process, node:http, Node built-ins only.
 *
 * A witness is an independent party that writes down, at the moment it is told, that a record with
 * a given fingerprint existed. It is given nothing else. Each install sends a seal — its public
 * key, the hash of the latest line of its local ledger, the number of lines, a time and a
 * signature — and gets back a signed receipt naming a position in the witness's own hash chain.
 * A self-held log rests on its holder's word; a log whose head was witnessed continuously cannot be
 * rewritten or backfilled afterwards without the gap showing.
 *
 * Two files, deliberately different:
 *   seals.jsonl  PRIVATE. The full seal messages (the fingerprints), so the witness can answer
 *                questions about one install and rebuild its state on restart.
 *   chain.jsonl  PUBLIC. Per entry only { i, t, leaf, prev, hash, sig }, where leaf is the sha256
 *                of the canonical seal. Publishing it reveals nothing about any install; a key
 *                holder recomputes their own leaf from their stored receipt and proves inclusion.
 *
 * What the witness never keeps: IP addresses. They are used in memory for rate limiting and are
 * never written to disk or to a log. The process logs one line at start-up and nothing per request.
 *
 * Endpoints: POST /v1/seal, POST /v1/near-miss, GET /v1/head, GET /v1/chain, GET /v1/tally,
 * GET /r/<install id> (receipt page, noindex), GET /r/<install id>/feed.xml (weekly Atom digest).
 * Deployment and environment: witness-server/README.md.
 */

import http from 'node:http'
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonical, sha256 } from '../scripts/sentinel/ledger.mjs'
import { ensureKey, installIdOf, signString, verifyMessage } from '../scripts/sentinel/keys.mjs'
import { VERSION } from '../scripts/sentinel/home.mjs'

export const CATEGORIES = ['destructive_command', 'credential_exposure', 'unreviewed_push', 'injection_suspected', 'other']
const CATEGORY_LABEL = {
  destructive_command: 'Destructive command',
  credential_exposure: 'Credential exposure',
  unreviewed_push: 'Unreviewed push',
  injection_suspected: 'Injection suspected',
  other: 'Other',
}
const SEAL_KEYS = ['head', 'pub', 'seq', 'sig', 'ts', 'v']
const NM_REQUIRED = ['category', 'pub', 'sig', 'ts', 'v']
const HEX64 = /^[0-9a-f]{64}$/
const B64URL = /^[A-Za-z0-9_-]+$/
const ID_RX = /^[0-9a-f]{32}$/
const MAX_BODY = 2048
const TS_SKEW_MS = 10 * 60_000
const PAGE_MAX = 1000

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

function isoSecond(ms) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z')
}

/** ISO-8601 week key, e.g. 2026-W39, and the Monday it starts on (UTC). */
export function isoWeek(ms) {
  const d = new Date(ms)
  const day = (d.getUTCDay() + 6) % 7 // Monday = 0
  const monday = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day)
  const thursday = new Date(monday + 3 * 86400_000)
  const year = thursday.getUTCFullYear()
  const jan4 = Date.UTC(year, 0, 4)
  const jan4Monday = jan4 - ((new Date(jan4).getUTCDay() + 6) % 7) * 86400_000
  const week = 1 + Math.round((monday - jan4Monday) / (7 * 86400_000))
  return { key: `${year}-W${String(week).padStart(2, '0')}`, start: monday }
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

function readLines(file) {
  if (!existsSync(file)) return []
  const out = []
  for (const l of readFileSync(file, 'utf8').split('\n')) {
    if (!l.trim()) continue
    try {
      out.push(JSON.parse(l))
    } catch {
      /* a torn last line after a crash: skip it */
    }
  }
  return out
}

function validPub(pub) {
  return typeof pub === 'string' && B64URL.test(pub) && Buffer.from(pub, 'base64url').length === 32
}

// ---------------------------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------------------------

/**
 * @param {object} o
 * @param {string} o.dataDir              where the key, seals.jsonl, chain.jsonl and near-misses.jsonl live
 * @param {string} [o.publicUrl]          e.g. https://witness.aivigilia.com (links on pages and in feeds)
 * @param {boolean} [o.trustProxy]        take the client address from X-Forwarded-For (behind Caddy)
 * @param {() => number} [o.now]
 * @param {number} [o.sealIntervalMs]     minimum time between two seals from one key (default 10 s)
 * @param {number} [o.nearMissIntervalMs] minimum time between two near-misses from one key (default 2 s)
 * @param {{capacity:number, perSec:number}} [o.ipBucket]
 */
export function createWitness(o) {
  const dataDir = path.resolve(o.dataDir)
  const publicUrl = String(o.publicUrl || 'http://127.0.0.1').replace(/\/+$/, '')
  const now = o.now || (() => Date.now())
  const sealIntervalMs = o.sealIntervalMs ?? 10_000
  const nearMissIntervalMs = o.nearMissIntervalMs ?? 2_000
  const bucketCfg = o.ipBucket || { capacity: 60, perSec: 1 }
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const files = {
    key: path.join(dataDir, 'server-ed25519.pem'),
    seals: path.join(dataDir, 'seals.jsonl'),
    chain: path.join(dataDir, 'chain.jsonl'),
    nearMisses: path.join(dataDir, 'near-misses.jsonl'),
  }
  const key = ensureKey(files.key)

  // In-memory state, rebuilt from disk on start. The chain is the authority.
  const chain = readLines(files.chain)
  const installs = new Map() // pub -> install
  const byId = new Map() // install id -> pub
  const networkNearMisses = [] // { t, category } — no key, for the weekly aggregate
  const lastNearMissAt = new Map() // pub -> ms
  const buckets = new Map() // ip -> { tokens, at }   (memory only; never written)

  function install(pub) {
    let r = installs.get(pub)
    if (!r) {
      r = { id: installIdOf(pub), first: null, lastAt: null, lastSeq: 0, lastHead: null, seals: 0, regressions: 0, rewrites: 0, weeks: new Map(), nearMiss: {} }
      installs.set(pub, r)
      byId.set(r.id, pub)
    }
    return r
  }

  function recordSeal(seal, tMs, flags) {
    const r = install(seal.pub)
    if (r.first == null) r.first = tMs
    r.lastAt = tMs
    r.seals++
    if (flags.regress) r.regressions++
    if (flags.rewrite) r.rewrites++
    r.lastSeq = seal.seq
    r.lastHead = seal.head
    const w = isoWeek(tMs)
    const wk = r.weeks.get(w.key) || { start: w.start, seals: 0, lastSeq: 0, lastAt: 0 }
    wk.seals++
    wk.lastSeq = seal.seq
    wk.lastAt = tMs
    r.weeks.set(w.key, wk)
  }

  for (const s of readLines(files.seals)) {
    if (!(Number.isInteger(s.i) && s.i < chain.length)) continue // written, but its chain entry was not
    recordSeal(s.seal, Date.parse(s.t), { regress: s.regress, rewrite: s.rewrite })
  }
  for (const n of readLines(files.nearMisses)) {
    const tMs = Date.parse(n.t)
    const r = install(n.pub)
    r.nearMiss[n.category] = (r.nearMiss[n.category] || 0) + 1
    networkNearMisses.push({ t: tMs, category: n.category })
  }

  function appendChain(leaf, tMs) {
    const i = chain.length
    const prev = i ? chain[i - 1].hash : null
    const t = isoSecond(tMs)
    const hash = sha256(canonical({ i, t, leaf, prev }))
    const entry = { i, t, leaf, prev, hash, sig: signString(key.privateKey, hash) }
    appendFileSync(files.chain, JSON.stringify(entry) + '\n', { mode: 0o644 })
    chain.push(entry)
    return entry
  }

  // --- rate limiting (memory only) ----------------------------------------------------------
  function clientAddress(req) {
    if (o.trustProxy) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean)
      if (xff.length) return xff[xff.length - 1]
    }
    return req.socket.remoteAddress || 'unknown'
  }

  function takeToken(ip) {
    const t = now()
    let b = buckets.get(ip)
    if (!b) {
      b = { tokens: bucketCfg.capacity, at: t }
      buckets.set(ip, b)
    }
    b.tokens = Math.min(bucketCfg.capacity, b.tokens + ((t - b.at) / 1000) * bucketCfg.perSec)
    b.at = t
    if (b.tokens < 1) return false
    b.tokens -= 1
    return true
  }

  const sweeper = setInterval(() => {
    const t = now()
    for (const [ip, b] of buckets) if (t - b.at > 10 * 60_000) buckets.delete(ip)
  }, 60_000)
  sweeper.unref()

  // --- responses ----------------------------------------------------------------------------
  function send(res, status, body, headers = {}) {
    const isStr = typeof body === 'string'
    const data = Buffer.from(isStr ? body : JSON.stringify(body))
    res.writeHead(status, {
      'content-type': isStr ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
      'content-length': data.length,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...headers,
    })
    res.end(data)
  }
  const jsonErr = (res, status, error, headers) => send(res, status, { error }, headers)

  function readBody(req) {
    return new Promise((resolve) => {
      const chunks = []
      let size = 0
      let over = false
      req.on('data', (c) => {
        size += c.length
        if (size > MAX_BODY) over = true
        else chunks.push(c)
      })
      req.on('end', () => resolve(over ? { over: true } : { text: Buffer.concat(chunks).toString('utf8') }))
      req.on('error', () => resolve({ over: true }))
    })
  }

  function checkTs(ts) {
    if (typeof ts !== 'string' || ts.length > 40) return 'ts must be an ISO time'
    const ms = Date.parse(ts)
    if (!Number.isFinite(ms)) return 'ts must be an ISO time'
    if (Math.abs(ms - now()) > TS_SKEW_MS) return 'ts is more than 10 minutes from the witness clock'
    return null
  }

  // --- POST /v1/seal ------------------------------------------------------------------------
  function handleSeal(res, body) {
    const keys = Object.keys(body).sort()
    if (keys.join(',') !== SEAL_KEYS.join(',')) return jsonErr(res, 400, 'a seal is exactly {v,pub,head,seq,ts,sig}')
    if (body.v !== 1) return jsonErr(res, 400, 'v must be 1')
    if (!validPub(body.pub)) return jsonErr(res, 400, 'pub must be a base64url raw ed25519 key')
    if (typeof body.head !== 'string' || !HEX64.test(body.head)) return jsonErr(res, 400, 'head must be sha256 hex')
    if (!Number.isInteger(body.seq) || body.seq < 1 || body.seq > 1e12) return jsonErr(res, 400, 'seq must be a positive integer')
    const tsErr = checkTs(body.ts)
    if (tsErr) return jsonErr(res, 400, tsErr)
    if (typeof body.sig !== 'string' || !B64URL.test(body.sig) || !verifyMessage(body.pub, body)) return jsonErr(res, 401, 'bad signature')
    const r = installs.get(body.pub)
    const t = now()
    if (r?.lastAt != null && t - r.lastAt < sealIntervalMs) {
      const wait = Math.ceil((sealIntervalMs - (t - r.lastAt)) / 1000)
      return jsonErr(res, 429, 'too soon for this key', { 'retry-after': String(wait) })
    }
    // A count that goes backwards, or the same count with a different head, is recorded and flagged,
    // never silently accepted: that is the evidence the witness exists to produce.
    const flags = {}
    if (r && body.seq < r.lastSeq) flags.regress = true
    if (r && body.seq === r.lastSeq && body.head !== r.lastHead) flags.rewrite = true
    const seal = { v: body.v, pub: body.pub, head: body.head, seq: body.seq, ts: body.ts, sig: body.sig }
    const leaf = sha256(canonical(seal))
    const i = chain.length
    const t2 = isoSecond(t)
    appendFileSync(files.seals, JSON.stringify({ i, t: t2, seal, ...flags }) + '\n', { mode: 0o600 })
    const entry = appendChain(leaf, t)
    recordSeal(seal, t, flags)
    const receipt = { i: entry.i, t: entry.t, leaf: entry.leaf, prev: entry.prev, hash: entry.hash, server_sig: entry.sig, server_pub: key.pub }
    return send(res, 200, Object.keys(flags).length ? { receipt, flags } : { receipt })
  }

  // --- POST /v1/near-miss -------------------------------------------------------------------
  function handleNearMiss(res, body) {
    const keys = Object.keys(body)
    const extra = keys.filter((k) => !NM_REQUIRED.includes(k) && k !== 'entry')
    if (extra.length || !NM_REQUIRED.every((k) => keys.includes(k))) return jsonErr(res, 400, 'a near-miss is exactly {v,pub,category,entry?,ts,sig}')
    if (body.v !== 1) return jsonErr(res, 400, 'v must be 1')
    if (!validPub(body.pub)) return jsonErr(res, 400, 'pub must be a base64url raw ed25519 key')
    if (!CATEGORIES.includes(body.category)) return jsonErr(res, 400, `category must be one of ${CATEGORIES.join(', ')}`)
    if ('entry' in body && (typeof body.entry !== 'string' || !HEX64.test(body.entry))) return jsonErr(res, 400, 'entry must be sha256 hex')
    const tsErr = checkTs(body.ts)
    if (tsErr) return jsonErr(res, 400, tsErr)
    if (typeof body.sig !== 'string' || !B64URL.test(body.sig) || !verifyMessage(body.pub, body)) return jsonErr(res, 401, 'bad signature')
    const t = now()
    const last = lastNearMissAt.get(body.pub)
    if (last != null && t - last < nearMissIntervalMs) return jsonErr(res, 429, 'too soon for this key', { 'retry-after': String(Math.ceil(nearMissIntervalMs / 1000)) })
    lastNearMissAt.set(body.pub, t)
    const rec = { t: isoSecond(t), pub: body.pub, category: body.category }
    if (body.entry) rec.entry = body.entry
    appendFileSync(files.nearMisses, JSON.stringify(rec) + '\n', { mode: 0o600 })
    const r = install(body.pub)
    r.nearMiss[body.category] = (r.nearMiss[body.category] || 0) + 1
    networkNearMisses.push({ t, category: body.category })
    return send(res, 200, { counted: true, category: body.category })
  }

  // --- aggregates ---------------------------------------------------------------------------
  function weekAggregate() {
    const since = now() - 7 * 86400_000
    const out = {}
    for (const n of networkNearMisses) if (n.t >= since) out[n.category] = (out[n.category] || 0) + 1
    return out
  }

  function tally() {
    let seals = 0
    let actions = 0
    let active = 0
    const since = now() - 7 * 86400_000
    for (const r of installs.values()) {
      if (!r.seals) continue
      seals += r.seals
      actions += r.lastSeq
      if (r.lastAt >= since) active++
    }
    const nm = {}
    for (const n of networkNearMisses) nm[n.category] = (nm[n.category] || 0) + 1
    return {
      installs: [...installs.values()].filter((r) => r.seals).length,
      installs_active_7d: active,
      seals,
      actions_witnessed: actions,
      near_misses: nm,
      near_misses_7d: weekAggregate(),
      chain_length: chain.length,
      generated: isoSecond(now()),
    }
  }

  // --- pages --------------------------------------------------------------------------------
  const FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=Space+Mono:wght@400;700&display=swap">'
  const CSS = `:root{--white:#fff;--black:#000;--red:#9E2B25;--g1:#F4F4F4;--g2:#E5E5E5;--g4:#767676;--g5:#333;--text:'Space Grotesk',system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;--mono:'Space Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box;border-radius:0;box-shadow:none}
html{background:var(--white);color:var(--black)}
body{margin:0;font:16px/24px var(--text);background:var(--white);color:var(--black)}
main{max-width:880px;margin:0 auto;padding:40px 16px 64px}
.label{font:11px/16px var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--g5)}
.label.red{color:var(--red)}
h1{font:700 40px/48px var(--text);margin:8px 0 8px;letter-spacing:-.01em}
h2{font:700 20px/32px var(--text);margin:48px 0 8px;border-top:2px solid var(--black);padding-top:16px}
.id{font:14px/24px var(--mono);word-break:break-all;color:var(--g5)}
.figs{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin-top:32px;border-top:1px solid var(--black)}
.fig{padding:16px 16px 16px 0;border-bottom:1px solid var(--g2)}
.fig .n{font:700 32px/40px var(--mono);display:block;margin-top:8px}
.fig .n.small{font-size:18px;line-height:40px}
table{border-collapse:collapse;width:100%;margin-top:8px}
th,td{text-align:left;padding:8px 0;border-bottom:1px solid var(--g2);vertical-align:top}
th{font:11px/16px var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--g5);font-weight:400}
td.num{font-family:var(--mono);text-align:right}
p{margin:8px 0;max-width:640px}
.muted{color:var(--g4)}
.flag{background:var(--black);color:var(--white);padding:16px;margin-top:32px}
.flag .label{color:#D9483F}
a{color:var(--black);text-decoration:underline;text-underline-offset:3px;transition:color 140ms cubic-bezier(.2,0,0,1)}
a:hover{color:var(--red)}
code{font:14px/24px var(--mono);background:var(--g1);padding:0 4px}
footer{margin-top:64px;padding-top:16px;border-top:1px solid var(--black)}
@media (max-width:640px){.figs{grid-template-columns:repeat(2,1fr)}h1{font-size:32px;line-height:40px}}`

  function page(title, bodyHtml) {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>${esc(title)}</title>${FONTS}<style>${CSS}</style></head><body><main>${bodyHtml}<footer><p class="label">Vigilia witness · sentinel-hook ${VERSION}</p><p class="muted">Kept by Vigilia, <a href="https://aivigilia.com">aivigilia.com</a>. Only fingerprints reach this witness; the records stay on the machines that wrote them. <a href="https://aivigilia.com/witness/privacy">Privacy</a>.</p></footer></main></body></html>`
  }
  const pageHeaders = { 'x-robots-tag': 'noindex, nofollow', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" }

  const fmtDate = (ms) => new Date(ms).toISOString().slice(0, 10)
  const fmtMinute = (ms) => new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
  const n = (x) => Number(x).toLocaleString('en-US')

  function receiptPage(id) {
    const r = installs.get(byId.get(id))
    const week = weekAggregate()
    const weekRows = CATEGORIES.filter((c) => week[c]).map((c) => `<tr><td>${esc(CATEGORY_LABEL[c])}</td><td class="num">${n(week[c])}</td></tr>`).join('')
    const own = CATEGORIES.filter((c) => r.nearMiss[c]).map((c) => `<tr><td>${esc(CATEGORY_LABEL[c])}</td><td class="num">${n(r.nearMiss[c])}</td></tr>`).join('')
    const sealed = r.seals > 0
    const flag = r.regressions || r.rewrites
      ? `<div class="flag"><p class="label">On the record</p><p>${r.regressions ? `The count this install sent went backwards ${n(r.regressions)} time${r.regressions === 1 ? '' : 's'}. ` : ''}${r.rewrites ? `The same count arrived with a different fingerprint ${n(r.rewrites)} time${r.rewrites === 1 ? '' : 's'}. ` : ''}A witness records that. It does not explain it: a reinstall starts a new count, and so does a rewritten history.</p></div>`
      : ''
    const body = `<p class="label red">Receipt</p><h1>What the witness saw</h1><p class="id">Install ${esc(id)}</p>
<div class="figs"><div class="fig"><span class="label">Actions witnessed</span><span class="n">${sealed ? n(r.lastSeq) : '––'}</span></div><div class="fig"><span class="label">Seals</span><span class="n">${n(r.seals)}</span></div><div class="fig"><span class="label">First seen</span><span class="n small">${r.first ? fmtDate(r.first) : '––'}</span></div><div class="fig"><span class="label">Last sealed</span><span class="n small">${r.lastAt ? fmtMinute(r.lastAt) : '––'}</span></div></div>
${sealed ? '' : '<p class="muted">No seal has arrived from this install yet.</p>'}
${flag}
${own ? `<h2>Near misses reported by this install</h2><p class="muted">Sent by the install itself, one coarse category each. Nothing else about them reached the witness.</p><table><thead><tr><th>Category</th><th style="text-align:right">Reported</th></tr></thead><tbody>${own}</tbody></table>` : ''}
<h2>What the network saw this week</h2>${weekRows ? `<p class="muted">Near misses reported by every install over the last seven days, by category.</p><table><thead><tr><th>Category</th><th style="text-align:right">Reported</th></tr></thead><tbody>${weekRows}</tbody></table>` : '<p class="muted">No install reported a near miss in the last seven days. Reporting them is opt-in.</p>'}
<h2>How to verify</h2><p>The witness holds a fingerprint of your record, a count and a time. Your record stays on your machine. To check it against the witness's signed receipts, run <code>npx @vigilia/sentinel-hook verify</code>. What a seal proves, and what it does not: <a href="https://github.com/aivigilia/sentinel-hook/blob/main/docs/witness.md">docs/witness.md</a>.</p>
<p class="muted">Anyone holding this page's address can see the count and the last seal time. Weekly digest: <a href="${esc(publicUrl)}/r/${esc(id)}/feed.xml">Atom feed</a> — subscribing is the opt-in; there is no email.</p>`
    return page(`Receipt ${id.slice(0, 8)} · Vigilia witness`, body)
  }

  function notFoundPage() {
    return page('Not found · Vigilia witness', '<p class="label red">404</p><h1>No receipt here</h1><p>The witness has no seal from an install with this id. An id appears after the first seal is accepted.</p>')
  }

  function feed(id) {
    const r = installs.get(byId.get(id))
    const nowMs = now()
    const cur = isoWeek(nowMs)
    const entries = []
    if (r.first != null) {
      let prevSeq = 0
      const all = []
      for (let w = isoWeek(r.first).start; w <= cur.start; w += 7 * 86400_000) {
        const wk = isoWeek(w + 3 * 86400_000) // a Thursday avoids DST-free edge cases at week bounds
        const d = r.weeks.get(wk.key)
        const seals = d?.seals || 0
        const lastSeq = d ? d.lastSeq : prevSeq
        const actions = Math.max(0, lastSeq - prevSeq)
        all.push({ key: wk.key, start: w, seals, actions, lastAt: d?.lastAt || null, current: wk.key === cur.key })
        if (d) prevSeq = d.lastSeq
      }
      entries.push(...all.slice(-26).reverse())
    }
    const url = `${publicUrl}/r/${id}`
    const updated = new Date(r.lastAt || nowMs).toISOString()
    const items = entries.map((e) => {
      const title = e.seals ? `${e.key}: ${n(e.actions)} actions witnessed, ${n(e.seals)} seal${e.seals === 1 ? '' : 's'}${e.current ? ' (so far)' : ''}` : `${e.key}: no seal arrived${e.current ? ' (so far)' : ''}`
      const upd = new Date(e.lastAt || Math.min(e.start + 7 * 86400_000 - 1000, nowMs)).toISOString()
      const summary = e.seals ? `The witness received ${n(e.seals)} seal${e.seals === 1 ? '' : 's'} from this install in ISO week ${e.key}, covering ${n(e.actions)} new action${e.actions === 1 ? '' : 's'}.` : `No seal from this install reached the witness in ISO week ${e.key}. A week without a seal is on the record too.`
      return `<entry><id>${esc(url)}#${e.key}</id><title>${esc(title)}</title><updated>${upd}</updated><link href="${esc(url)}"/><summary>${esc(summary)}</summary></entry>`
    }).join('')
    return `<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"><id>${esc(url)}/feed.xml</id><title>Vigilia witness · install ${esc(id.slice(0, 8))} · weekly</title><updated>${updated}</updated><author><name>Vigilia witness</name></author><link rel="self" href="${esc(url)}/feed.xml"/><link href="${esc(url)}"/>${items}</feed>\n`
  }

  function homePage() {
    const t = tally()
    return page('Vigilia witness', `<p class="label red">Witness</p><h1>A free Swiss witness for your coding agent</h1><p>This server records fingerprints of what coding agents do, at the moment they do it: a hash of the latest line of a record that stays on the user's machine, a count, a time and a signature. Nothing else reaches it.</p><div class="figs"><div class="fig"><span class="label">Installs</span><span class="n">${n(t.installs)}</span></div><div class="fig"><span class="label">Seals</span><span class="n">${n(t.seals)}</span></div><div class="fig"><span class="label">Actions witnessed</span><span class="n">${n(t.actions_witnessed)}</span></div><div class="fig"><span class="label">Chain length</span><span class="n">${n(t.chain_length)}</span></div></div><h2>Read the chain</h2><p><a href="/v1/head">/v1/head</a> · <a href="/v1/chain">/v1/chain</a> · <a href="/v1/tally">/v1/tally</a></p><p class="muted">Source and documentation: <a href="https://github.com/aivigilia/sentinel-hook">github.com/aivigilia/sentinel-hook</a>.</p>`)
  }

  // --- router -------------------------------------------------------------------------------
  async function handler(req, res) {
    try {
      const u = new URL(req.url, 'http://witness.local')
      const p = u.pathname
      if (req.method === 'POST' && (p === '/v1/seal' || p === '/v1/near-miss')) {
        if (!takeToken(clientAddress(req))) return jsonErr(res, 429, 'too many requests', { 'retry-after': '5' })
        const { over, text } = await readBody(req)
        if (over) return jsonErr(res, 413, 'body over 2 KB', { connection: 'close' })
        let body
        try {
          body = JSON.parse(text)
        } catch {
          return jsonErr(res, 400, 'body is not JSON')
        }
        if (!body || typeof body !== 'object' || Array.isArray(body)) return jsonErr(res, 400, 'body must be a JSON object')
        return p === '/v1/seal' ? handleSeal(res, body) : handleNearMiss(res, body)
      }
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        if (['/v1/seal', '/v1/near-miss', '/v1/head', '/v1/chain', '/v1/tally'].includes(p)) return jsonErr(res, 405, 'method not allowed', { allow: p.startsWith('/v1/seal') || p.startsWith('/v1/near') ? 'POST' : 'GET' })
        return jsonErr(res, 404, 'not found')
      }
      if (!takeToken(clientAddress(req))) return jsonErr(res, 429, 'too many requests', { 'retry-after': '5' })
      if (p === '/') return send(res, 200, homePage(), pageHeaders)
      if (p === '/healthz') return send(res, 200, { ok: true, chain_length: chain.length })
      if (p === '/v1/head') {
        if (!chain.length) return send(res, 200, { empty: true, server_pub: key.pub })
        return send(res, 200, { ...chain[chain.length - 1], server_pub: key.pub })
      }
      if (p === '/v1/chain') {
        const from = Math.max(0, parseInt(u.searchParams.get('from') ?? '0', 10) || 0)
        const toRaw = u.searchParams.get('to')
        const to = Math.min(chain.length, from + PAGE_MAX, toRaw != null ? Math.max(from, (parseInt(toRaw, 10) || 0)) : Infinity)
        return send(res, 200, { from, to, total: chain.length, server_pub: key.pub, entries: chain.slice(from, to) })
      }
      if (p === '/v1/tally') return send(res, 200, tally())
      const m = /^\/r\/([^/]+)(\/feed\.xml)?\/?$/.exec(p)
      if (m) {
        const id = m[1]
        if (!ID_RX.test(id) || !byId.has(id) || !installs.get(byId.get(id)).seals) {
          return m[2] ? send(res, 404, 'not found', { 'content-type': 'text/plain; charset=utf-8', 'x-robots-tag': 'noindex, nofollow' }) : send(res, 404, notFoundPage(), pageHeaders)
        }
        if (m[2]) return send(res, 200, feed(id), { 'content-type': 'application/atom+xml; charset=utf-8', 'x-robots-tag': 'noindex, nofollow' })
        return send(res, 200, receiptPage(id), pageHeaders)
      }
      return jsonErr(res, 404, 'not found')
    } catch {
      try {
        jsonErr(res, 500, 'internal error')
      } catch {
        /* the socket is gone */
      }
    }
  }

  const server = http.createServer(handler)
  server.headersTimeout = 10_000
  server.requestTimeout = 15_000
  return { server, handler, serverPub: key.pub, tally, files, close: () => new Promise((r) => { clearInterval(sweeper); server.close(() => r()) }) }
}

// ---------------------------------------------------------------------------------------------
// Run directly
// ---------------------------------------------------------------------------------------------

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8787)
  const host = process.env.HOST || '127.0.0.1'
  const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data')
  const w = createWitness({ dataDir, publicUrl: process.env.PUBLIC_URL || `http://${host}:${port}`, trustProxy: process.env.TRUST_PROXY === '1' })
  w.server.listen(port, host, () => {
    // The only line this process ever prints. No request is logged, so no address is either.
    process.stdout.write(`witness ${VERSION} listening on http://${host}:${port} · data ${dataDir} · server key ${w.serverPub}\n`)
  })
  const stop = () => w.close().then(() => process.exit(0))
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
}

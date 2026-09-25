// node --test witness-server/test.mjs — the witness server, in process, on 127.0.0.1.
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { after, before, test } from 'node:test'
import { canonical, sha256 } from '../scripts/sentinel/ledger.mjs'
import { installIdOf, rawPublic, signMessage, verifyString } from '../scripts/sentinel/keys.mjs'
import { buildNearMiss, buildSeal, checkReceipt } from '../scripts/sentinel/witness-client.mjs'
import { listen, tempDir } from '../scripts/sentinel/test-helpers.mjs'
import { createWitness, isoWeek } from './server.mjs'

function newKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const pub = rawPublic(publicKey)
  return { privateKey, publicKey, pub, installId: installIdOf(pub) }
}
const head = (s) => sha256('line ' + s)

let clock = Date.parse('2026-09-24T12:00:00Z')
const now = () => clock
const tick = (ms) => (clock += ms)
const iso = () => new Date(clock).toISOString()

let dataDir
let w
let base

async function post(p, body, headers = {}) {
  const res = await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) })
  let json = null
  const text = await res.text()
  try {
    json = JSON.parse(text)
  } catch {
    /* html */
  }
  return { status: res.status, json, text, headers: res.headers }
}
const get = async (p) => {
  const res = await fetch(base + p)
  return { status: res.status, text: await res.text(), headers: res.headers }
}

before(async () => {
  dataDir = tempDir('witness-data-')
  w = createWitness({ dataDir, publicUrl: 'https://witness.example.invalid', now, sealIntervalMs: 10_000, ipBucket: { capacity: 1000, perSec: 100 } })
  base = await listen(w.server)
})
after(async () => {
  await w.close()
})

test('a well-formed, well-signed seal is accepted and answered with a verifiable receipt', async () => {
  const k = newKey()
  const seal = buildSeal(k, { head: head(1), seq: 1, ts: iso() })
  const r = await post('/v1/seal', seal)
  assert.equal(r.status, 200)
  assert.equal(checkReceipt(seal, r.json.receipt).ok, true)
  assert.equal(r.json.receipt.server_pub, w.serverPub)
  assert.equal(r.json.flags, undefined)
})

test('a bad signature is rejected, and so is a seal signed by another key', async () => {
  const k = newKey()
  const other = newKey()
  const seal = buildSeal(k, { head: head(2), seq: 3, ts: iso() })
  assert.equal((await post('/v1/seal', { ...seal, seq: 4 })).status, 401) // tampered after signing
  const forged = { ...seal, sig: signMessage(other.privateKey, { v: 1, pub: k.pub, head: head(2), seq: 3, ts: seal.ts }) }
  assert.equal((await post('/v1/seal', forged)).status, 401)
  assert.equal((await post('/v1/seal', { ...seal, sig: 'AAAA' })).status, 401)
})

test('unknown or missing keys are rejected; so are bad types, stale times and oversized bodies', async () => {
  const k = newKey()
  const seal = buildSeal(k, { head: head(3), seq: 1, ts: iso() })
  assert.equal((await post('/v1/seal', { ...seal, cwd: '/Users/alice' })).status, 400)
  const { seq, ...noSeq } = seal
  assert.equal((await post('/v1/seal', noSeq)).status, 400)
  assert.equal((await post('/v1/seal', 'not json')).status, 400)
  assert.equal((await post('/v1/seal', [seal])).status, 400)
  const stale = buildSeal(k, { head: head(3), seq: 1, ts: new Date(clock - 11 * 60_000).toISOString() })
  assert.equal((await post('/v1/seal', stale)).status, 400)
  const badHead = buildSeal(k, { head: 'git push --force', seq: 1, ts: iso() })
  assert.equal((await post('/v1/seal', badHead)).status, 400)
  const big = await post('/v1/seal', JSON.stringify({ ...seal, pad: 'x'.repeat(3000) }))
  assert.equal(big.status, 413)
  assert.ok(big.text.length < 100, 'JSON errors are short')
})

test('per-key rate limit: a second seal inside 10 s is refused, after 10 s accepted', async () => {
  const k = newKey()
  assert.equal((await post('/v1/seal', buildSeal(k, { head: head(10), seq: 1, ts: iso() }))).status, 200)
  const again = await post('/v1/seal', buildSeal(k, { head: head(11), seq: 2, ts: iso() }))
  assert.equal(again.status, 429)
  assert.ok(Number(again.headers.get('retry-after')) > 0)
  tick(10_000)
  assert.equal((await post('/v1/seal', buildSeal(k, { head: head(11), seq: 2, ts: iso() }))).status, 200)
})

test('per-IP token bucket', async () => {
  const d = tempDir('witness-ip-')
  const small = createWitness({ dataDir: d, now, sealIntervalMs: 0, ipBucket: { capacity: 3, perSec: 0 } })
  const b = await listen(small.server)
  const codes = []
  for (let i = 0; i < 5; i++) codes.push((await fetch(b + '/v1/tally')).status)
  assert.deepEqual(codes, [200, 200, 200, 429, 429])
  await small.close()
})

test('a sequence that goes backwards is recorded and flagged, not silently accepted; so is a rewrite', async () => {
  const k = newKey()
  assert.equal((await post('/v1/seal', buildSeal(k, { head: head(20), seq: 50, ts: iso() }))).status, 200)
  tick(10_000)
  const back = await post('/v1/seal', buildSeal(k, { head: head(21), seq: 7, ts: iso() }))
  assert.equal(back.status, 200)
  assert.deepEqual(back.json.flags, { regress: true })
  tick(10_000)
  const rewrite = await post('/v1/seal', buildSeal(k, { head: head(22), seq: 7, ts: iso() }))
  assert.deepEqual(rewrite.json.flags, { rewrite: true })
  const lines = readFileSync(path.join(dataDir, 'seals.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  assert.ok(lines.some((l) => l.seal.pub === k.pub && l.regress === true))
  const page = await get('/r/' + k.installId)
  assert.match(page.text, /went backwards 1 time/)
})

test('the public chain verifies and holds no pub, head, seq, ts or sig of any seal', async () => {
  const r = await get('/v1/chain')
  const { entries, server_pub, total } = JSON.parse(r.text)
  assert.ok(total >= 5)
  let prev = null
  entries.forEach((e, i) => {
    assert.deepEqual(Object.keys(e).sort(), ['hash', 'i', 'leaf', 'prev', 'sig', 't'])
    assert.equal(e.i, i)
    assert.equal(e.prev, prev)
    assert.equal(e.hash, sha256(canonical({ i: e.i, t: e.t, leaf: e.leaf, prev: e.prev })))
    assert.ok(verifyString(server_pub, e.hash, e.sig))
    assert.match(e.t, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/)
    prev = e.hash
  })
  const onDisk = readFileSync(path.join(dataDir, 'chain.jsonl'), 'utf8')
  const seals = readFileSync(path.join(dataDir, 'seals.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l).seal)
  for (const s of seals) {
    for (const v of [s.pub, s.head, s.sig]) assert.ok(!onDisk.includes(v), 'the public chain must not carry seal fields')
    assert.ok(!r.text.includes(s.pub) && !r.text.includes(s.head))
  }
  assert.ok(!/"(pub|head|seq|ts)"/.test(onDisk))
  const h = JSON.parse((await get('/v1/head')).text)
  assert.equal(h.hash, entries[entries.length - 1].hash)
  assert.ok(verifyString(h.server_pub, h.hash, h.sig))
  // private files are private
  assert.equal(statSync(path.join(dataDir, 'seals.jsonl')).mode & 0o077, 0)
  assert.equal(statSync(path.join(dataDir, 'server-ed25519.pem')).mode & 0o077, 0)
})

test('chain paging is bounded', async () => {
  const r = JSON.parse((await get('/v1/chain?from=1&to=3')).text)
  assert.equal(r.entries.length, 2)
  assert.equal(r.entries[0].i, 1)
  const huge = JSON.parse((await get('/v1/chain?from=0&to=999999')).text)
  assert.ok(huge.entries.length <= 1000)
})

test('near-miss: enum-checked, exact keys, signed, rate-limited, counted', async () => {
  const k = newKey()
  const nm = buildNearMiss(k, { category: 'destructive_command', entry: head(30), ts: iso() })
  assert.equal((await post('/v1/near-miss', nm)).status, 200)
  assert.equal((await post('/v1/near-miss', buildNearMiss(k, { category: 'other', ts: iso() }))).status, 429)
  tick(3000)
  assert.equal((await post('/v1/near-miss', buildNearMiss(k, { category: 'other', ts: iso() }))).status, 200)
  tick(3000)
  const bad = { v: 1, pub: k.pub, category: 'rm -rf ~', ts: iso() }
  assert.equal((await post('/v1/near-miss', { ...bad, sig: signMessage(k.privateKey, bad) })).status, 400)
  const withText = { v: 1, pub: k.pub, category: 'other', ts: iso(), note: 'the agent ran rm -rf' }
  assert.equal((await post('/v1/near-miss', { ...withText, sig: signMessage(k.privateKey, withText) })).status, 400)
  assert.equal((await post('/v1/near-miss', { ...nm, category: 'other' })).status, 401)
  assert.throws(() => buildNearMiss(k, { category: 'nope' }))
  const t = JSON.parse((await get('/v1/tally')).text)
  assert.equal(t.near_misses.destructive_command, 1)
  assert.equal(t.near_misses.other, 1)
})

test('receipt page: 200 for a known id, a real 404 for an unknown one; noindex; honest content', async () => {
  const k = newKey()
  tick(10_000)
  await post('/v1/seal', buildSeal(k, { head: head(40), seq: 12, ts: iso() }))
  const page = await get('/r/' + k.installId)
  assert.equal(page.status, 200)
  assert.match(page.headers.get('x-robots-tag'), /noindex/)
  assert.match(page.text, /<meta name="robots" content="noindex,nofollow">/)
  assert.match(page.text, />12</)
  assert.match(page.text, /What the network saw this week/)
  assert.ok(!/agents? stopped/i.test(page.text))
  assert.ok(!page.text.includes(k.pub))
  assert.equal((await get('/r/' + 'f'.repeat(32))).status, 404)
  assert.equal((await get('/r/not-an-id')).status, 404)
  assert.equal((await get('/r/' + 'f'.repeat(32) + '/feed.xml')).status, 404)
  const feed = await get('/r/' + k.installId + '/feed.xml')
  assert.equal(feed.status, 200)
  assert.match(feed.headers.get('content-type'), /atom/)
  assert.match(feed.text, /<entry><id>[^<]+#\d{4}-W\d\d<\/id>/)
  assert.equal((await get('/nope')).status, 404)
})

test('tally sums: installs, seals, actions witnessed (latest seq per key)', async () => {
  const d = tempDir('witness-tally-')
  const t = createWitness({ dataDir: d, now, sealIntervalMs: 0 })
  const b = await listen(t.server)
  const a = newKey()
  const c = newKey()
  const send = (k, s) => fetch(b + '/v1/seal', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(buildSeal(k, { head: head(s), seq: s, ts: iso() })) })
  await send(a, 5)
  await send(a, 9)
  await send(c, 4)
  const tally = await (await fetch(b + '/v1/tally')).json()
  assert.equal(tally.installs, 2)
  assert.equal(tally.seals, 3)
  assert.equal(tally.actions_witnessed, 13)
  await t.close()
  // State survives a restart: rebuilt from disk.
  const t2 = createWitness({ dataDir: d, now, sealIntervalMs: 0 })
  assert.equal(t2.tally().actions_witnessed, 13)
  assert.equal(t2.tally().chain_length, 3)
  await t2.close().catch(() => {})
})

test('no IP address is ever written to disk', async () => {
  const all = ['seals.jsonl', 'chain.jsonl', 'near-misses.jsonl'].map((f) => {
    try {
      return readFileSync(path.join(dataDir, f), 'utf8')
    } catch {
      return ''
    }
  }).join('\n')
  assert.ok(!all.includes('127.0.0.1') && !all.includes('::1') && !all.includes('::ffff'))
})

test('ISO weeks', () => {
  assert.equal(isoWeek(Date.parse('2026-09-24T12:00:00Z')).key, '2026-W39')
  assert.equal(isoWeek(Date.parse('2027-01-01T00:00:00Z')).key, '2026-W53')
  assert.equal(isoWeek(Date.parse('2026-01-01T00:00:00Z')).key, '2026-W01')
})

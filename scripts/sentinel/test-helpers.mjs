/**
 * test-helpers.mjs — shared by the 0.4.0 tests. Everything here exists so that no test can ever
 * touch the real ~/.claude, ~/.vigilia or ~/.cursor of the machine it runs on: every HOME is a
 * fresh mkdtemp under the OS temp directory, and `hookEnv()` refuses anything else.
 */

import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import http from 'node:http'
import { fileURLToPath } from 'node:url'

export const HERE = path.dirname(fileURLToPath(import.meta.url))
export const ROOT = path.resolve(HERE, '..', '..')
export const CLI = path.join(ROOT, 'bin', 'cli.mjs')
export const WITNESS_HOOK = path.join(HERE, 'witness.mjs')
export const GATE_HOOK = path.join(HERE, 'sentinel.mjs')
const TMP = realpathSync(tmpdir())

/** A fresh temporary directory; `home` ones get a ~/.claude so Claude Code is "detected". */
export function tempDir(prefix = 'sentinel-') {
  return realpathSync(mkdtempSync(path.join(TMP, prefix)))
}

export function assertTemp(dir) {
  const real = realpathSync(dir)
  assert.ok(real.startsWith(TMP + path.sep), `refusing to use a HOME outside the temp directory: ${real}`)
}

/** The environment for a child process: HOME is the temp dir, and nothing of ours leaks in. */
export function hookEnv(home, extra = {}) {
  assertTemp(home)
  const env = { ...process.env }
  for (const k of Object.keys(env)) {
    if (k.startsWith('VIGILIA_') || k.startsWith('GIT_') || k === 'XDG_CONFIG_HOME' || k === 'CLAUDE_PROJECT_DIR') delete env[k]
  }
  return { ...env, HOME: home, ...extra }
}

export function runSync(file, args, { home, input = '', cwd, env } = {}) {
  const t0 = process.hrtime.bigint()
  const r = spawnSync(process.execPath, [file, ...args], { input, cwd: cwd || home, env: env || hookEnv(home), encoding: 'utf8', timeout: 30_000 })
  return { ...r, ms: Number(process.hrtime.bigint() - t0) / 1e6 }
}

export function runAsync(file, args, { home, input = '', cwd, env } = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [file, ...args], { cwd: cwd || home, env: env || hookEnv(home) })
    let stdout = ''
    let stderr = ''
    c.stdout.on('data', (d) => (stdout += d))
    c.stderr.on('data', (d) => (stderr += d))
    c.on('close', (status) => resolve({ status, stdout, stderr }))
    c.stdin.end(input)
  })
}

/** Run `fn` over `items` with at most `n` in flight. */
export async function pool(items, n, fn) {
  const out = new Array(items.length)
  let i = 0
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) {
      const k = i++
      out[k] = await fn(items[k], k)
    }
  }))
  return out
}

/**
 * Put `witness.handler` behind a server that records every request exactly as it arrived:
 * method, url, headers, raw body. Returns { url, captured, close }.
 */
export async function captureServer(witness) {
  const captured = []
  const server = http.createServer(async (req, res) => {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const body = Buffer.concat(chunks)
    captured.push({ method: req.method, url: req.url, headers: { ...req.headers }, rawHeaders: [...req.rawHeaders], body: body.toString('utf8') })
    const replay = Readable.from(body.length ? [body] : [])
    Object.assign(replay, { method: req.method, url: req.url, headers: req.headers, socket: req.socket })
    witness.handler(replay, res)
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${server.address().port}`, captured, close: () => new Promise((r) => server.close(() => r())) }
}

export async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return `http://127.0.0.1:${server.address().port}`
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export async function waitFor(pred, { timeoutMs = 8000, stepMs = 50 } = {}) {
  const end = Date.now() + timeoutMs
  for (;;) {
    const v = await pred()
    if (v) return v
    if (Date.now() > end) return v
    await sleep(stepMs)
  }
}

export function median(xs) {
  const s = [...xs].sort((a, b) => a - b)
  const m = s.length >> 1
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

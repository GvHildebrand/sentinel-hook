/**
 * trigger.mjs — start the flusher without waiting for it.
 *
 * The hook is on the agent's hot path, so it never touches the network. After appending its line
 * it calls `maybeFlush()`: if the last flush attempt was more than a minute ago (a stamp file's
 * mtime, one stat), it touches the stamp and spawns `flush.mjs` detached, with no stdio, and
 * returns at once. The flusher does the network work in its own process and outlives the hook.
 */

import { spawn } from 'node:child_process'
import { statSync, utimesSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ensureDir, paths, readConfig, witnessEnabled } from './home.mjs'

const FLUSHER = path.join(path.dirname(fileURLToPath(import.meta.url)), 'flush.mjs')
export const FLUSH_INTERVAL_MS = 60_000

export function spawnFlusher(args = [], env = process.env) {
  try {
    spawn(process.execPath, [FLUSHER, ...args], { detached: true, stdio: 'ignore', env }).unref()
    return true
  } catch {
    return false
  }
}

/** Spawn the flusher if the witness is on and (unless `always`) the last attempt is over a minute old. */
export function maybeFlush({ env = process.env, always = false, cfg = readConfig(env) } = {}) {
  if (!witnessEnabled(cfg, env)) return false
  const p = paths(env)
  const now = Date.now()
  if (!always) {
    try {
      if (now - statSync(p.flushStamp).mtimeMs < FLUSH_INTERVAL_MS) return false
    } catch {
      /* no stamp yet */
    }
  }
  try {
    ensureDir(p.root, 0o700)
    try {
      const t = new Date(now)
      utimesSync(p.flushStamp, t, t)
    } catch {
      writeFileSync(p.flushStamp, '')
    }
  } catch {
    return false
  }
  return spawnFlusher([], env)
}

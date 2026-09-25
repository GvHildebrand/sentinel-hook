/**
 * home.mjs — where an installed sentinel keeps its things, and the small files that describe it.
 *
 * Everything lives under `~/.vigilia/`, never inside the user's repository: a ledger written into a
 * repo is one `git add -A` away from being published by accident, and the key that signs the seals
 * must never be anywhere a push could carry it.
 *
 *   ~/.vigilia/config.json            mode, witness URL, opt-ins, which settings files we touched
 *   ~/.vigilia/keys/ed25519.pem       the install's private key (0600, dir 0700) — never sent
 *   ~/.vigilia/ledger/witness.jsonl   the local chain: the user's own evidence
 *   ~/.vigilia/receipts.jsonl         the witness's signed receipts, one per accepted seal
 *   ~/.vigilia/state.json             flush bookkeeping: last attempt, backoff, last sealed head
 *   ~/.vigilia/sentinel-hook/<ver>/   the runtime the hooks point at (`current` is a symlink)
 *
 * HOME is read from the environment on every call, so a test (or a cautious user) can point the
 * whole thing at a temporary directory with `HOME=…`. Node built-ins only.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'

export const VERSION = '0.4.0'
export const DEFAULT_WITNESS_URL = 'https://witness.aivigilia.com'
export const PRIVACY_URL = 'https://aivigilia.com/witness/privacy'
/** The marker by which our hook entries are recognised in a settings file. */
export const HOOK_MARKER = '/.vigilia/sentinel-hook/'

export function homeDir(env = process.env) {
  return env.HOME || homedir()
}

export function paths(env = process.env) {
  const root = path.join(homeDir(env), '.vigilia')
  return {
    root,
    config: path.join(root, 'config.json'),
    keysDir: path.join(root, 'keys'),
    key: path.join(root, 'keys', 'ed25519.pem'),
    ledgerDir: env.VIGILIA_SENTINEL_LEDGER_DIR || path.join(root, 'ledger'),
    ledger: path.join(env.VIGILIA_SENTINEL_LEDGER_DIR || path.join(root, 'ledger'), 'witness.jsonl'),
    receipts: path.join(root, 'receipts.jsonl'),
    state: path.join(root, 'state.json'),
    flushStamp: path.join(root, 'flush.stamp'),
    flushLock: path.join(root, 'flush.lock'),
    pendingNearMiss: path.join(root, 'near-miss-pending.jsonl'),
    runtimeRoot: path.join(root, 'sentinel-hook'),
    runtimeCurrent: path.join(root, 'sentinel-hook', 'current'),
  }
}

export function readJson(file, fallback = null) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return fallback
  }
}

/** Write JSON atomically (temp file + rename), so a reader never sees half a file. */
export function writeJson(file, obj, mode) {
  mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', mode ? { mode } : undefined)
  renameSync(tmp, file)
  if (mode) chmodSync(file, mode)
}

export function readConfig(env = process.env) {
  return readJson(paths(env).config, null)
}

export function writeConfig(cfg, env = process.env) {
  writeJson(paths(env).config, cfg, 0o600)
}

export function readState(env = process.env) {
  return readJson(paths(env).state, {}) || {}
}

export function writeState(state, env = process.env) {
  writeJson(paths(env).state, state, 0o600)
}

/**
 * Is the network part of the witness on? Only with a config written by `init` (that is the
 * consent), `witness` not false, and VIGILIA_WITNESS not `off`. Anything else is local-only.
 */
export function witnessEnabled(cfg, env = process.env) {
  if (!cfg) return false
  if (String(env.VIGILIA_WITNESS || '').toLowerCase() === 'off') return false
  if (cfg.witness === false) return false
  return Boolean(cfg.witness_url)
}

export function receiptUrl(cfg, installId) {
  const base = String(cfg?.witness_url || DEFAULT_WITNESS_URL).replace(/\/+$/, '')
  return `${base}/r/${installId}`
}

export function ensureDir(dir, mode) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode })
  if (mode) {
    try {
      chmodSync(dir, mode)
    } catch {
      /* not ours to fix */
    }
  }
}

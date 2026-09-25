/**
 * install.mjs — what `init` and `uninstall` do to a machine, kept apart from the CLI's printing
 * so it can be tested with a temporary HOME.
 *
 * Rules the installer keeps, because it edits a file the user owns (~/.claude/settings.json):
 *   - The runtime is copied to ~/.vigilia/sentinel-hook/<version>/ with a `current` symlink, and the
 *     hooks point there. The npx cache is ephemeral; a hook that points into it breaks silently.
 *   - The settings file is backed up (settings.json.vigilia-backup-<timestamp>) before any edit.
 *   - Our entries are recognised by the marker `/.vigilia/sentinel-hook/` in the command path. A
 *     re-run replaces them in place of duplicating them; the user's other hooks are never removed
 *     or reordered.
 *   - A settings file that is not valid JSON is not touched: the installer says how to fix it and
 *     exits non-zero, rather than guess.
 *   - Nothing is written on --dry-run.
 *
 * Agents. Claude Code is the only agent hooked in 0.4.0. Cursor and Codex are detected and named,
 * and not hooked; docs/witness.md says why (the short version: neither has been run against a live
 * install of that agent yet, and a malformed hooks file in a stranger's editor is a harm a witness
 * must not cause).
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { DEFAULT_WITNESS_URL, HOOK_MARKER, VERSION, ensureDir, homeDir, paths, readConfig, writeConfig } from './home.mjs'
import { ensureKey } from './keys.mjs'

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

/** The files an installed hook needs at run time. Everything else in the package stays behind. */
export const RUNTIME_FILES = [
  'package.json',
  'LICENSE',
  'bin/cli.mjs',
  'scripts/sentinel/witness.mjs',
  'scripts/sentinel/sentinel.mjs',
  'scripts/sentinel/rules.mjs',
  'scripts/sentinel/ledger.mjs',
  'scripts/sentinel/home.mjs',
  'scripts/sentinel/keys.mjs',
  'scripts/sentinel/trigger.mjs',
  'scripts/sentinel/flush.mjs',
  'scripts/sentinel/witness-client.mjs',
  'scripts/sentinel/install.mjs',
]

export const GATE_MATCHER = 'Bash|Write|Edit|MultiEdit|NotebookEdit|Read'

// ---------------------------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------------------------

export function onPath(name, env = process.env) {
  for (const dir of String(env.PATH || '').split(path.delimiter)) {
    if (!dir) continue
    try {
      const f = path.join(dir, name)
      if (statSync(f).isFile()) return true
    } catch {
      /* not here */
    }
  }
  return false
}

export function detectAgents(env = process.env) {
  const h = homeDir(env)
  return {
    'claude-code': existsSync(path.join(h, '.claude')) || onPath('claude', env),
    cursor: existsSync(path.join(h, '.cursor')) || onPath('cursor', env),
    codex: existsSync(path.join(h, '.codex')) || onPath('codex', env),
  }
}

// ---------------------------------------------------------------------------------------------
// Runtime copy
// ---------------------------------------------------------------------------------------------

export function copyRuntime(env = process.env, { from = PKG_ROOT } = {}) {
  const p = paths(env)
  ensureDir(p.root, 0o700)
  const dest = path.join(p.runtimeRoot, VERSION)
  for (const rel of RUNTIME_FILES) {
    const src = path.join(from, rel)
    if (!existsSync(src)) {
      if (rel === 'LICENSE') continue
      throw new Error(`runtime file missing from the package: ${rel}`)
    }
    mkdirSync(path.dirname(path.join(dest, rel)), { recursive: true })
    copyFileSync(src, path.join(dest, rel))
  }
  // `current` → <version>, replaced atomically. If symlinks are unavailable, hooks use the versioned path.
  let hookRoot = p.runtimeCurrent
  try {
    const tmp = `${p.runtimeCurrent}.${process.pid}.tmp`
    rmSync(tmp, { force: true })
    symlinkSync(VERSION, tmp, 'dir')
    renameSync(tmp, p.runtimeCurrent)
  } catch {
    hookRoot = dest
  }
  return { dest, hookRoot }
}

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

export function hookCommand(hookRoot, mode, agent = 'claude-code') {
  const entry = mode === 'gate' ? 'sentinel.mjs' : 'witness.mjs'
  const file = path.join(hookRoot, 'scripts', 'sentinel', entry)
  return `node "${file}" --agent ${agent}`
}

const isOurs = (h) => typeof h?.command === 'string' && h.command.includes(HOOK_MARKER)

/** Remove every hook entry of ours; drop matcher groups and events that only we filled. */
export function removeOurHooks(settings) {
  const s = structuredClone(settings ?? {})
  if (!s.hooks || typeof s.hooks !== 'object') return s
  for (const ev of Object.keys(s.hooks)) {
    const groups = s.hooks[ev]
    if (!Array.isArray(groups)) continue
    const kept = []
    for (const g of groups) {
      if (!g || !Array.isArray(g.hooks)) {
        kept.push(g)
        continue
      }
      const hs = g.hooks.filter((h) => !isOurs(h))
      if (hs.length === g.hooks.length) kept.push(g)
      else if (hs.length) kept.push({ ...g, hooks: hs })
    }
    if (kept.length) s.hooks[ev] = kept
    else delete s.hooks[ev]
  }
  if (!Object.keys(s.hooks).length) delete s.hooks
  return s
}

/** Our entries for a mode, appended after the user's own. */
export function addOurHooks(settings, mode, command) {
  const s = removeOurHooks(settings)
  s.hooks ??= {}
  const hook = { type: 'command', command, timeout: mode === 'gate' ? 10 : 5 }
  const events = [
    ['SessionStart', null],
    ['SubagentStart', null],
    ['PreToolUse', mode === 'gate' ? GATE_MATCHER : '*'],
    ['SessionEnd', null],
  ]
  for (const [ev, matcher] of events) {
    const group = matcher ? { matcher, hooks: [{ ...hook }] } : { hooks: [{ ...hook }] }
    s.hooks[ev] = [...(Array.isArray(s.hooks[ev]) ? s.hooks[ev] : []), group]
  }
  return s
}

export function hasOurHooks(settings) {
  return JSON.stringify(settings ?? {}).includes(HOOK_MARKER)
}

/** Read a settings file. { ok, exists, data, indent, error } — never throws. */
export function readSettings(file) {
  if (!existsSync(file)) return { ok: true, exists: false, data: {}, indent: 2, trailingNewline: true }
  const text = readFileSync(file, 'utf8')
  if (!text.trim()) return { ok: true, exists: true, data: {}, indent: 2, trailingNewline: true }
  try {
    const data = JSON.parse(text)
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { ok: false, exists: true, error: 'the top level is not a JSON object' }
    const m = /\n([ \t]+)"/.exec(text)
    return { ok: true, exists: true, data, indent: m ? m[1] : 2, trailingNewline: text.endsWith('\n') }
  } catch (err) {
    return { ok: false, exists: true, error: String(err?.message || err) }
  }
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-')
}

/**
 * Apply `edit` to the settings file. Backs it up first if it exists and would change.
 * Returns { changed, backup, file } or { error }.
 */
export function editSettings(file, edit, { dryRun = false } = {}) {
  const cur = readSettings(file)
  if (!cur.ok) return { error: cur.error, file }
  const next = edit(cur.data)
  if (JSON.stringify(next) === JSON.stringify(cur.data)) return { changed: false, file }
  if (dryRun) return { changed: true, file, dryRun: true }
  mkdirSync(path.dirname(file), { recursive: true })
  let backup = null
  if (cur.exists) {
    backup = `${file}.vigilia-backup-${stamp()}`
    copyFileSync(file, backup)
  }
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify(next, null, cur.indent) + (cur.trailingNewline ? '\n' : ''))
  renameSync(tmp, file)
  return { changed: true, backup, file }
}

export function userSettingsFile(env = process.env) {
  return path.join(homeDir(env), '.claude', 'settings.json')
}

export function projectSettingsFile(cwd = process.cwd()) {
  return path.join(path.resolve(cwd), '.claude', 'settings.json')
}

// ---------------------------------------------------------------------------------------------
// init / uninstall
// ---------------------------------------------------------------------------------------------

/**
 * @returns {{ ok: boolean, code: number, mode, settingsFile, detected, installId?, backup?, error?, dryRun? }}
 */
export function init({ env = process.env, cwd = process.cwd(), gate = false, project = false, offline = false, witnessUrl, dryRun = false } = {}) {
  const mode = gate ? 'gate' : 'witness'
  const detected = detectAgents(env)
  const settingsFile = project ? projectSettingsFile(cwd) : userSettingsFile(env)
  if (!detected['claude-code'] && !project) {
    return { ok: false, code: 1, mode, detected, settingsFile, error: 'Claude Code was not found (no ~/.claude directory and no `claude` on PATH). Nothing was installed.' }
  }
  const pre = readSettings(settingsFile)
  if (!pre.ok) {
    return { ok: false, code: 2, mode, detected, settingsFile, error: `${settingsFile} is not valid JSON (${pre.error}). Nothing was changed. Fix the file, or move it aside, and run init again.` }
  }
  const url = String(witnessUrl || readConfig(env)?.witness_url || DEFAULT_WITNESS_URL).replace(/\/+$/, '')
  try {
    // eslint-disable-next-line no-new
    new URL(url)
  } catch {
    return { ok: false, code: 2, mode, detected, settingsFile, error: `--witness-url is not a URL: ${url}` }
  }
  const p = paths(env)
  if (dryRun) {
    const hookRoot = p.runtimeCurrent
    const r = editSettings(settingsFile, (s) => addOurHooks(s, mode, hookCommand(hookRoot, mode)), { dryRun: true })
    return { ok: true, code: 0, mode, detected, settingsFile, dryRun: true, wouldChange: r.changed, witnessUrl: url, offline }
  }
  const { hookRoot } = copyRuntime(env)
  const key = ensureKey(p.key)
  const r = editSettings(settingsFile, (s) => addOurHooks(s, mode, hookCommand(hookRoot, mode)))
  if (r.error) return { ok: false, code: 2, mode, detected, settingsFile, error: r.error }
  const prev = readConfig(env) || {}
  const settingsFiles = [...new Set([...(prev.settings_files || []), settingsFile])]
  const cfg = {
    mode,
    witness: !offline,
    witness_url: url,
    share_near_misses: prev.share_near_misses === true && !offline,
    install_id: key.installId,
    agents: ['claude-code'],
    settings_files: settingsFiles,
    installed: true,
    installed_at: prev.installed_at || new Date().toISOString(),
    updated_at: new Date().toISOString(),
    version: VERSION,
  }
  writeConfig(cfg, env)
  ensureDir(p.ledgerDir, 0o700)
  return { ok: true, code: 0, mode, detected, settingsFile, installId: key.installId, backup: r.backup, changed: r.changed, witnessUrl: url, offline, hookRoot }
}

export function uninstall({ env = process.env, cwd = process.cwd() } = {}) {
  const cfg = readConfig(env)
  const candidates = [...new Set([...(cfg?.settings_files || []), userSettingsFile(env), projectSettingsFile(cwd)])]
  const removed = []
  const errors = []
  for (const f of candidates) {
    if (!existsSync(f)) continue
    const cur = readSettings(f)
    if (!cur.ok) {
      if (cfg?.settings_files?.includes(f)) errors.push({ file: f, error: cur.error })
      continue
    }
    if (!hasOurHooks(cur.data)) continue
    const r = editSettings(f, removeOurHooks)
    if (r.error) errors.push({ file: f, error: r.error })
    else if (r.changed) removed.push({ file: f, backup: r.backup })
  }
  if (cfg) writeConfig({ ...cfg, installed: false, settings_files: errors.map((e) => e.file), updated_at: new Date().toISOString() }, env)
  return { removed, errors, paths: paths(env) }
}

/** Every settings.json backup we have made next to a file (for tests and for status). */
export function backupsOf(file) {
  const dir = path.dirname(file)
  if (!existsSync(dir)) return []
  return readdirSync(dir).filter((n) => n.startsWith(path.basename(file) + '.vigilia-backup-')).map((n) => path.join(dir, n))
}

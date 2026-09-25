#!/usr/bin/env node
/**
 * cli.mjs — `npx @vigilia/sentinel-hook <command>`.
 *
 *   init [--gate] [--project] [--offline] [--witness-url URL] [--dry-run] [--yes]
 *   uninstall | status | verify | receipt | help
 *   near-miss <category> [--entry <hash>]      send one opt-in near-miss (this command is the opt-in)
 *   near-miss --auto on|off                    gate mode: share each deny/ask's category automatically
 *   flush [--force]                            seal the latest head now (the hook does this by itself)
 *
 * Output is short on purpose: what happened, what leaves the machine, where the receipt is. The
 * reasoning lives in docs/, not in the terminal.
 */

import { createInterface } from 'node:readline'
import { existsSync, readFileSync, rmSync } from 'node:fs'
import { lineHashes, verify } from '../scripts/sentinel/ledger.mjs'
import { PRIVACY_URL, VERSION, homeDir, paths, readConfig, readState, receiptUrl, witnessEnabled, writeConfig } from '../scripts/sentinel/home.mjs'
import { loadKey, verifyMessage } from '../scripts/sentinel/keys.mjs'
import { CATEGORIES, checkReceipt, flush, sendNearMiss } from '../scripts/sentinel/witness-client.mjs'
import { init, uninstall } from '../scripts/sentinel/install.mjs'

const out = (s = '') => process.stdout.write(s + '\n')
const err = (s = '') => process.stderr.write(s + '\n')
const tilde = (p) => {
  const h = homeDir()
  return h && p.startsWith(h + '/') ? '~' + p.slice(h.length) : p
}

function parse(argv) {
  const flags = {}
  const pos = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--witness-url' || a === '--entry' || a === '--auto') flags[a.slice(2)] = argv[++i]
    else if (a.startsWith('--witness-url=')) flags['witness-url'] = a.split('=').slice(1).join('=')
    else if (a.startsWith('--')) flags[a.slice(2)] = true
    else pos.push(a)
  }
  return { flags, pos }
}

const HELP = `sentinel-hook ${VERSION} — a free Swiss witness for your coding agent

  npx @vigilia/sentinel-hook init            witness every Claude Code session on this machine
  npx @vigilia/sentinel-hook init --gate     also allow/ask/deny before each call (can block real work)
  npx @vigilia/sentinel-hook status | verify | receipt | uninstall

init options: --project (this repository only) · --offline (local ledger, nothing sent)
              --witness-url URL · --dry-run (change nothing) · --yes (no question asked)
near-miss <${CATEGORIES.join('|')}> [--entry <hash>]   send one, by hand
near-miss --auto on|off                                 gate mode: share each deny/ask's category

Sent to the witness: a fingerprint of your record, a count, a timestamp and a signature.
Never sent: code, commands, prompts, file paths, repo names. ${PRIVACY_URL}`

async function confirm(question) {
  if (!process.stdin.isTTY) return true
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await new Promise((r) => rl.question(question, r))
  rl.close()
  return !/^n/i.test(String(answer).trim())
}

const SENT_LINE = 'Sent to the witness: a fingerprint of the record, a count, a timestamp and a signature. Never sent: code, commands, prompts, file paths, repo names.'
const GATE_LINE = 'Gate mode can block real work: a denied call does not run. `init` without --gate returns to witness only.'

function othersLine(detected) {
  const names = [detected.cursor && 'Cursor', detected.codex && 'Codex'].filter(Boolean)
  if (!names.length) return null
  return `${names.join(' and ')} detected — not yet supported by the witness; Claude Code only in ${VERSION}.`
}

async function cmdInit(flags) {
  const opts = { gate: !!flags.gate, project: !!flags.project, offline: !!flags.offline, witnessUrl: flags['witness-url'], dryRun: !!flags['dry-run'] }
  const where = (f) => (opts.project ? `this repository (${tilde(f)})` : `every session on this machine (${tilde(f)})`)
  const plan = await Promise.resolve(init({ ...opts, dryRun: true }))
  if (!plan.ok) {
    err(plan.error)
    return plan.code
  }
  const head = `${opts.gate ? 'Gate' : 'Witness'} for Claude Code: ${where(plan.settingsFile)}.`
  const sent = opts.offline ? 'Offline: nothing leaves this machine; the ledger is kept locally only.' : SENT_LINE
  if (opts.dryRun) {
    out(`Dry run, nothing written. ${head}`)
    out(sent)
    if (opts.gate) out(GATE_LINE)
    const o = othersLine(plan.detected)
    if (o) out(o)
    return 0
  }
  const asked = !flags.yes && process.stdin.isTTY
  if (asked) {
    out(head)
    out(sent)
    if (opts.gate) out(GATE_LINE)
    if (!(await confirm('Proceed? [Y/n] '))) {
      out('Nothing was changed.')
      return 1
    }
  }
  const r = init(opts)
  if (!r.ok) {
    err(r.error)
    return r.code
  }
  const cfg = readConfig()
  if (!asked) {
    out(`${opts.gate ? 'Gate' : 'Witness'} on for Claude Code: ${where(r.settingsFile)}.`)
    out(sent)
  }
  out(opts.offline ? `Ledger: ${tilde(paths().ledger)}` : `Your receipt: ${receiptUrl(cfg, r.installId)}`)
  out(`Privacy: ${PRIVACY_URL}`)
  if (opts.gate && !asked) out(GATE_LINE)
  const o = othersLine(r.detected)
  if (o) out(o)
  return 0
}

function cmdUninstall() {
  const r = uninstall()
  for (const e of r.errors) err(`${tilde(e.file)} is not valid JSON (${e.error}); our entries were not removed from it. Fix the file and run uninstall again.`)
  if (r.removed.length) for (const x of r.removed) out(`Removed the sentinel-hook entries from ${tilde(x.file)}${x.backup ? ` (backup: ${tilde(x.backup)})` : ''}.`)
  else if (!r.errors.length) out('No sentinel-hook entries found; nothing to remove.')
  out(`Your ledger and key stay on this machine: ${tilde(r.paths.ledger)}, ${tilde(r.paths.key)}.`)
  out(`To delete them, and everything else sentinel-hook kept, by hand: rm -rf ${tilde(r.paths.root)}`)
  return r.errors.length ? 2 : 0
}

function fmtTime(iso) {
  return iso ? iso.slice(0, 16).replace('T', ' ') + ' UTC' : 'never'
}

function cmdStatus() {
  const cfg = readConfig()
  const p = paths()
  const key = loadKey(p.key)
  if (!cfg) {
    out('Not installed. Run: npx @vigilia/sentinel-hook init')
    return 1
  }
  const v = verify(p.ledger)
  const st = readState()
  const hooked = cfg.installed ? `${(cfg.agents || []).join(', ') || 'none'} (${(cfg.settings_files || []).map(tilde).join(', ')})` : 'none (uninstalled)'
  out(`Mode: ${cfg.mode}${cfg.installed ? '' : ', hooks removed'} · agents hooked: ${hooked}`)
  out(`Ledger: ${tilde(p.ledger)} · ${v.lines} line${v.lines === 1 ? '' : 's'} · chain verified: ${v.ok ? 'yes' : v.why === 'missing' ? 'no ledger yet' : `NO (line ${v.brokenAt}: ${v.why})`}`)
  if (!witnessEnabled(cfg)) out('Witness: off — the ledger is local only.')
  else {
    const pending = st.last_sealed ? Math.max(0, v.lines - st.last_sealed.seq) : v.lines
    out(`Last seal: ${fmtTime(st.last_sealed?.at)}${st.last_sealed ? ` (line ${st.last_sealed.seq})` : ''} · not yet sealed: ${pending} line${pending === 1 ? '' : 's'}${st.last_error ? ` · last attempt failed: ${st.last_error}` : ''}`)
    out(`Near-miss sharing: ${cfg.share_near_misses ? 'on' : 'off'} · receipt: ${key ? receiptUrl(cfg, key.installId) : 'no key yet'}`)
  }
  return 0
}

function cmdVerify() {
  const p = paths()
  const key = loadKey(p.key)
  const v = verify(p.ledger)
  if (v.why === 'missing') {
    out(`No ledger at ${tilde(p.ledger)} yet.`)
    return 1
  }
  out(v.ok ? `Chain: ${v.lines} lines, intact.` : `Chain: BROKEN at line ${v.brokenAt} (${v.why}).`)
  let ok = v.ok
  if (!existsSync(p.receipts)) {
    out('Receipts: none yet (nothing has been sealed with the witness).')
    return ok ? 0 : 1
  }
  const hashes = lineHashes(p.ledger)
  let good = 0
  const bad = []
  const lines = readFileSync(p.receipts, 'utf8').split('\n').filter(Boolean)
  const serverKeys = new Set()
  for (const [n, l] of lines.entries()) {
    let r
    try {
      r = JSON.parse(l)
    } catch {
      bad.push(`receipt ${n + 1}: unreadable`)
      continue
    }
    const { seal, receipt } = r
    const c = checkReceipt(seal, receipt)
    if (!c.ok) bad.push(`receipt ${n + 1}: ${c.why}`)
    else if (!key || seal.pub !== key.pub) bad.push(`receipt ${n + 1}: sealed by a different key`)
    else if (!verifyMessage(seal.pub, seal)) bad.push(`receipt ${n + 1}: our own signature on the seal does not verify`)
    else if (hashes[seal.seq - 1] !== seal.head) bad.push(`receipt ${n + 1}: sealed head is not line ${seal.seq} of this chain`)
    else {
      good++
      serverKeys.add(receipt.server_pub)
    }
  }
  if (bad.length) ok = false
  out(`Receipts: ${good} of ${lines.length} check out${good ? ` — each signed by the witness (key ${[...serverKeys].map((k) => k.slice(0, 12) + '…').join(', ')}), each sealed head a line of this chain` : ''}.`)
  for (const b of bad.slice(0, 5)) out(`  ${b}`)
  if (bad.length > 5) out(`  … and ${bad.length - 5} more`)
  return ok ? 0 : 1
}

async function cmdNearMiss(flags, pos) {
  const cfg = readConfig()
  if (!cfg) {
    err('Not installed. Run: npx @vigilia/sentinel-hook init')
    return 1
  }
  if (flags.auto !== undefined) {
    const on = String(flags.auto).toLowerCase()
    if (on !== 'on' && on !== 'off') {
      err('Use: near-miss --auto on|off')
      return 2
    }
    writeConfig({ ...cfg, share_near_misses: on === 'on', updated_at: new Date().toISOString() })
    if (on === 'off') rmSync(paths().pendingNearMiss, { force: true })
    out(on === 'on'
      ? `Near-miss sharing on: in gate mode, each deny or ask sends one category (${CATEGORIES.join(', ')}) and the hash of its ledger line. Nothing else.${cfg.mode !== 'gate' ? ' You are in witness mode, which never decides, so nothing will be sent until you run init --gate.' : ''}`
      : 'Near-miss sharing off. Nothing is sent about decisions.')
    return 0
  }
  const category = pos[0]
  if (!CATEGORIES.includes(category)) {
    err(`Category must be one of: ${CATEGORIES.join(', ')}`)
    return 2
  }
  const entry = flags.entry
  if (entry !== undefined && !/^[0-9a-f]{64}$/.test(String(entry))) {
    err('--entry must be the 64-character hash of a line in your ledger.')
    return 2
  }
  if (entry && !lineHashes(paths().ledger).includes(entry)) {
    err('--entry is not the hash of any line in your ledger.')
    return 2
  }
  const r = await sendNearMiss({ category, entry })
  if (!r.ok) {
    err(`Not sent: ${r.error}`)
    return 1
  }
  out(`Sent one near-miss: ${category}${entry ? ` (line ${entry.slice(0, 12)}…)` : ''}. Nothing else about it left this machine.`)
  return 0
}

function cmdReceipt() {
  const cfg = readConfig()
  const key = loadKey(paths().key)
  if (!cfg || !key) {
    err('Not installed. Run: npx @vigilia/sentinel-hook init')
    return 1
  }
  out(receiptUrl(cfg, key.installId))
  return 0
}

async function cmdFlush(flags) {
  const r = await flush({ force: !!flags.force })
  const say = {
    sealed: () => `Sealed line ${r.seq} with the witness (chain entry ${r.receipt.i}).`,
    'nothing-new': () => 'Nothing new to seal.',
    'no-ledger': () => 'No ledger yet; nothing to seal.',
    off: () => 'Witness is off; the ledger is local only.',
    backoff: () => `Waiting after a failure; next attempt after ${fmtTime(r.next)} (use --force to try now).`,
    busy: () => 'Another flush is running.',
    'rate-limited': () => `The witness asked to wait; next attempt after ${fmtTime(r.next)}.`,
    failed: () => `Not sealed: ${r.error}. It will be retried; nothing was blocked.`,
  }
  out((say[r.status] || (() => r.status))())
  return r.status === 'failed' ? 1 : 0
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2)
  const { flags, pos } = parse(rest)
  switch (cmd) {
    case 'init':
      return cmdInit(flags)
    case 'uninstall':
      return cmdUninstall()
    case 'status':
      return cmdStatus()
    case 'verify':
      return cmdVerify()
    case 'near-miss':
      return cmdNearMiss(flags, pos)
    case 'receipt':
      return cmdReceipt()
    case 'flush':
      return cmdFlush(flags)
    case 'version':
    case '--version':
      out(VERSION)
      return 0
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      out(HELP)
      return 0
    default:
      err(`Unknown command: ${cmd}\n`)
      err(HELP)
      return 2
  }
}

main().then((code) => process.exit(code ?? 0), (e) => {
  err(`sentinel-hook: ${e?.message || e}`)
  process.exit(1)
})

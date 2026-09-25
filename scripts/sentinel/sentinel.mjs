#!/usr/bin/env node
/**
 * sentinel.mjs — the gate. Claude Code runs it on SessionStart, SubagentStart and PreToolUse
 * (see .claude/settings.json). It reads the hook input on stdin, decides with rules.mjs, writes one
 * line to the ledger, and prints the decision. Node built-ins only, so a lockfile drift can never
 * disable it.
 *
 * Since 0.4.0 this is the opt-in mode (`init --gate`). The default is witness.mjs, which records and
 * never decides. The gate's decisions are unchanged; what changes when the installer registers it
 * (it is then invoked with `--agent <name>`):
 *   - the record goes to ~/.vigilia/ledger/witness.jsonl, one chain for the install, never into the
 *     user's repository, and each line carries the witness fields (seq, nonce, agent,
 *     transcript_path, input_sha256) so the same chain can be sealed;
 *   - the chain head is sealed to the witness by the detached flusher, as in witness mode;
 *   - SessionEnd is recorded and triggers a flush;
 *   - with `share_near_misses` on (`near-miss --auto on`), each deny or ask sends one coarse
 *     category and the hash of its ledger line — nothing else.
 * Run from a repository checkout without `--agent`, it behaves exactly as 0.3.0 did.
 *
 *   SessionStart / SubagentStart  → a heartbeat line: the control was present, with this ruleset.
 *   PreToolUse                    → allow | ask | deny, before the tool runs.
 *
 * It fails OPEN: an internal error is written to the ledger as `event: "error"` and the call
 * proceeds. A sentinel that could take a fleet down by crashing would be uninstalled within a
 * week; a sentinel whose absence is itself on the record cannot hide the same way.
 *
 * Environment:
 *   VIGILIA_AGENT                 declared agent id (optional; else the git committer email decides)
 *   VIGILIA_SENTINEL_LEDGER_DIR   where the JSONL files go (default <repo>/research/sentinel/ledger;
 *                                 installed with --agent, ~/.vigilia/ledger/witness.jsonl)
 *   VIGILIA_SENTINEL_OBSERVE=1    observe mode: decide and record, but never deny or ask
 */

import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { append, canonical, excerpt, sha256 } from './ledger.mjs'
import { SENTINEL_VERSION, classifyIdentity, evaluate, rulesDigest } from './rules.mjs'
import { paths as homePaths, readConfig, witnessEnabled } from './home.mjs'
import { maybeFlush, spawnFlusher } from './trigger.mjs'
import { categoryForRule } from './witness-client.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))

function readStdin() {
  try {
    return readFileSync(0, 'utf8')
  } catch {
    return ''
  }
}

function findRepoRoot(cwd) {
  let d = path.resolve(cwd)
  for (let i = 0; i < 12; i++) {
    if (existsSync(path.join(d, '.git'))) return d
    const up = path.dirname(d)
    if (up === d) break
    d = up
  }
  // The sentinel lives in <repo>/scripts/sentinel; fall back to that.
  const own = path.resolve(HERE, '..', '..')
  return existsSync(path.join(own, '.git')) ? own : null
}

function gitEmail(cwd) {
  if (process.env.GIT_COMMITTER_EMAIL) return process.env.GIT_COMMITTER_EMAIL
  try {
    return execFileSync('git', ['-C', cwd, 'config', 'user.email'], { encoding: 'utf8', timeout: 2000 }).trim()
  } catch {
    return ''
  }
}

function loadInventory(repoRoot) {
  if (!repoRoot) return null
  const f = path.join(repoRoot, '_config', 'agents.json')
  try {
    return JSON.parse(readFileSync(f, 'utf8'))
  } catch {
    return null
  }
}

function hasHeartbeat(file, session) {
  if (!existsSync(file)) return false
  const needle = `"session":${JSON.stringify(session)}`
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (line.includes(needle) && line.includes('"kind":"heartbeat"')) return true
  }
  return false
}

function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown'
}

function argValue(name) {
  const i = process.argv.indexOf(name)
  return i !== -1 ? process.argv[i + 1] ?? null : null
}

function main() {
  const installedAgent = argValue('--agent')
  const installed = installedAgent != null
  const raw = readStdin()
  let input
  try {
    input = JSON.parse(raw)
  } catch {
    return // not a hook invocation; nothing to do
  }
  const cwd = input.cwd || process.cwd()
  const repoRoot = findRepoRoot(cwd)
  const inventory = loadInventory(repoRoot)
  const identity = classifyIdentity({ envAgent: process.env.VIGILIA_AGENT, email: gitEmail(cwd), inventory })
  let ledgerFile
  if (installed) {
    // Installed by the CLI: one chain per install, under ~/.vigilia/ledger/, never in the repository.
    ledgerFile = homePaths().ledger
  } else {
    const ledgerDir = process.env.VIGILIA_SENTINEL_LEDGER_DIR || (repoRoot ? path.join(repoRoot, 'research', 'sentinel', 'ledger') : path.join(process.env.HOME || '.', '.vigilia-sentinel'))
    ledgerFile = path.join(ledgerDir, (identity.kind === 'agent' ? identity.agent : `${identity.kind}-${slug(identity.email || 'anonymous')}`) + '.jsonl')
  }
  const cfg = installed ? readConfig() : null
  const opts = installed ? { seq: true } : {}
  const observe = process.env.VIGILIA_SENTINEL_OBSERVE === '1'
  const home = process.env.HOME || ''
  const shown = installed && home && ledgerFile.startsWith(home + path.sep)
    ? '~' + ledgerFile.slice(home.length)
    : path.relative(cwd, ledgerFile).startsWith('..') ? ledgerFile : path.relative(cwd, ledgerFile)

  const base = {
    v: 1,
    ts: new Date().toISOString(),
    event: input.hook_event_name,
    session: input.session_id || null,
    identity: { kind: identity.kind, agent: identity.agent, email: identity.email, via: identity.via },
    subagent: input.agent_id ? { id: input.agent_id, type: input.agent_type || null } : null,
    sentinel: { version: SENTINEL_VERSION, rules: rulesDigest(), mode: observe ? 'observe' : 'enforce' },
  }
  if (installed) {
    // The witness fields: a random nonce makes the line's hash unguessable, so the hash alone can be
    // sealed; transcript_path and input_sha256 bind the line to the agent's own transcript entry.
    Object.assign(base, {
      nonce: randomBytes(16).toString('hex'),
      agent: installedAgent,
      transcript_path: input.transcript_path ?? null,
      input_sha256: input.hook_event_name === 'PreToolUse' ? sha256(canonical(input.tool_input ?? {})) : null,
    })
  }

  try {
    if (input.hook_event_name === 'SessionStart' || input.hook_event_name === 'SubagentStart') {
      const rec = append(ledgerFile, { ...base, kind: 'heartbeat', model: input.model || null }, opts)
      if (installed) maybeFlush({ cfg })
      const line = `Vigilia sentinel ${SENTINEL_VERSION} is active (${observe ? 'observe' : 'enforce'} mode) for identity ${identity.kind}${identity.agent ? ':' + identity.agent : ''}. Every Bash, Write, Edit and Read call is evaluated against declared scope and a destructive-command ruleset and recorded in ${shown}. Record ${rec.hash.slice(0, 12)}.`
      process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: input.hook_event_name, additionalContext: line } }))
      return
    }

    if (installed && input.hook_event_name === 'SessionEnd') {
      append(ledgerFile, { ...base, kind: 'session-end' }, opts)
      maybeFlush({ cfg, always: true })
      return
    }
    if (input.hook_event_name !== 'PreToolUse') return
    // A routine sets its git identity a few calls into its run, so its SessionStart heartbeat lands
    // in the unconfigured ledger. When an identity first resolves for this session, write a
    // heartbeat under it too, so the attester's cross-check finds one under the agent's own name.
    // Installed, there is one chain for every identity, so the SessionStart heartbeat is already in it.
    if (!installed && input.session_id && !hasHeartbeat(ledgerFile, input.session_id)) {
      append(ledgerFile, { ...base, event: 'IdentityResolved', kind: 'heartbeat', note: 'identity first resolved during this session' })
    }
    const tool = input.tool_name
    const verdict = evaluate({ tool, input: input.tool_input || {}, identity, cwd, repoRoot, inventory })
    const target = tool === 'Bash' ? excerpt(input.tool_input?.command ?? '') : excerpt(input.tool_input?.file_path ?? input.tool_input?.notebook_path ?? input.tool_input?.path ?? '')
    const targetHash = tool === 'Bash' ? sha256(String(input.tool_input?.command ?? '')) : null
    const applied = observe && verdict.decision !== 'allow' ? 'allow' : verdict.decision
    const rec = append(ledgerFile, {
      ...base,
      kind: 'decision',
      tool,
      tool_use_id: input.tool_use_id || null,
      target,
      target_sha256: targetHash,
      decision: applied,
      would: observe ? verdict.decision : undefined,
      rule: verdict.rule,
      severity: verdict.severity,
      reason: verdict.reason,
      findings: verdict.findings,
    }, opts)
    if (installed) {
      maybeFlush({ cfg })
      // Opt-in only: one coarse category and the hash of this line. Never the command, never the rule's reason.
      if (applied !== 'allow' && cfg?.share_near_misses && witnessEnabled(cfg)) {
        spawnFlusher(['--near-miss', categoryForRule(verdict.rule, tool === 'Bash' ? input.tool_input?.command : ''), rec.hash])
      }
    }
    if (applied === 'allow') return
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: applied,
          permissionDecisionReason: `Vigilia sentinel ${applied === 'deny' ? 'blocked' : 'held'} this call — rule ${verdict.rule}: ${verdict.reason}. Record ${rec.hash.slice(0, 12)} in ${shown}.`,
        },
      }),
    )
  } catch (err) {
    try {
      append(ledgerFile, { ...base, kind: 'error', error: String(err?.message || err).slice(0, 300) }, opts)
    } catch {
      /* nothing left to do */
    }
  }
}

main()

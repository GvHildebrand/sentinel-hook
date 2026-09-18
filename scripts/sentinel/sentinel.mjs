#!/usr/bin/env node
/**
 * sentinel.mjs — the hook. Claude Code runs it on SessionStart, SubagentStart and PreToolUse
 * (see .claude/settings.json). It reads the hook input on stdin, decides with rules.mjs, writes one
 * line to the ledger, and prints the decision. Node built-ins only, so a lockfile drift can never
 * disable it.
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
 *   VIGILIA_SENTINEL_LEDGER_DIR   where the JSONL files go (default <repo>/research/sentinel/ledger)
 *   VIGILIA_SENTINEL_OBSERVE=1    observe mode: decide and record, but never deny or ask
 */

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { append, excerpt, sha256 } from './ledger.mjs'
import { SENTINEL_VERSION, classifyIdentity, evaluate, rulesDigest } from './rules.mjs'

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

function slug(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown'
}

function main() {
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
  const ledgerDir = process.env.VIGILIA_SENTINEL_LEDGER_DIR || (repoRoot ? path.join(repoRoot, 'research', 'sentinel', 'ledger') : path.join(process.env.HOME || '.', '.vigilia-sentinel'))
  const ledgerFile = path.join(ledgerDir, (identity.kind === 'agent' ? identity.agent : `${identity.kind}-${slug(identity.email || 'anonymous')}`) + '.jsonl')
  const observe = process.env.VIGILIA_SENTINEL_OBSERVE === '1'
  const shown = path.relative(cwd, ledgerFile).startsWith('..') ? ledgerFile : path.relative(cwd, ledgerFile)

  const base = {
    v: 1,
    ts: new Date().toISOString(),
    event: input.hook_event_name,
    session: input.session_id || null,
    identity: { kind: identity.kind, agent: identity.agent, email: identity.email, via: identity.via },
    subagent: input.agent_id ? { id: input.agent_id, type: input.agent_type || null } : null,
    sentinel: { version: SENTINEL_VERSION, rules: rulesDigest(), mode: observe ? 'observe' : 'enforce' },
  }

  try {
    if (input.hook_event_name === 'SessionStart' || input.hook_event_name === 'SubagentStart') {
      const rec = append(ledgerFile, { ...base, kind: 'heartbeat', model: input.model || null })
      const line = `Vigilia sentinel ${SENTINEL_VERSION} is active (${observe ? 'observe' : 'enforce'} mode) for identity ${identity.kind}${identity.agent ? ':' + identity.agent : ''}. Every Bash, Write, Edit and Read call is evaluated against declared scope and a destructive-command ruleset and recorded in ${shown}. Record ${rec.hash.slice(0, 12)}.`
      process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: input.hook_event_name, additionalContext: line } }))
      return
    }

    if (input.hook_event_name !== 'PreToolUse') return
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
    })
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
      append(ledgerFile, { ...base, kind: 'error', error: String(err?.message || err).slice(0, 300) })
    } catch {
      /* nothing left to do */
    }
  }
}

main()

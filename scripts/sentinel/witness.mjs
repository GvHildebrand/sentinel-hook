#!/usr/bin/env node
/**
 * witness.mjs — the witness hook, the default mode since 0.4.0.
 *
 * It observes and records. It does not decide. There is no code path in this file, or in anything
 * it imports, that prints a permission decision — not deny, not ask, and not allow either: an
 * explicit "allow" from a hook would silently override the agent's own permission prompt, which a
 * witness has no business doing. It does not import rules.mjs at all; a test walks its import graph
 * to keep it that way. It prints nothing, ever: no decision, no context line, no noise. Exit 0.
 *
 * For every SessionStart, SubagentStart, PreToolUse (every tool) and SessionEnd it appends one line
 * to ~/.vigilia/ledger/witness.jsonl:
 *
 *   v, ts, seq, nonce, event, agent, session, tool, tool_use_id, transcript_path,
 *   input_sha256 (sha256 of the canonical JSON of the full tool_input),
 *   target (a bounded, redacted excerpt of the command or path), prev, hash
 *
 * `transcript_path` and `tool_use_id` bind the line to the agent's own transcript entry, and
 * `input_sha256` lets the user show later that the transcript's tool call is the one recorded. The
 * random `nonce` makes the line's hash unguessable, which is what allows that hash — and nothing
 * else — to be sent to the witness.
 *
 * Then, at most once a minute (and always on SessionEnd), it spawns the detached flusher and exits.
 * No network on the hot path. Fails open: an internal error becomes an `error` line, never a block.
 *
 *   --agent <name>   which coding agent runs this hook (the installer passes claude-code)
 */

import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { append, canonical, excerpt, sha256 } from './ledger.mjs'
import { VERSION, paths, readConfig } from './home.mjs'
import { maybeFlush } from './trigger.mjs'

process.on('uncaughtException', () => process.exit(0))

function arg(name) {
  const i = process.argv.indexOf(name)
  return i !== -1 ? process.argv[i + 1] ?? null : null
}

function targetOf(input) {
  const ti = input.tool_input || {}
  if (input.tool_name === 'Bash') return excerpt(ti.command ?? '')
  const p = ti.file_path ?? ti.notebook_path ?? ti.path ?? null
  return p == null ? null : excerpt(p)
}

const WITNESSED = new Set(['SessionStart', 'SubagentStart', 'PreToolUse', 'SessionEnd'])

function main() {
  let raw = ''
  try {
    raw = readFileSync(0, 'utf8')
  } catch {
    return
  }
  let input
  try {
    input = JSON.parse(raw)
  } catch {
    return // not a hook invocation; nothing to do
  }
  if (!input || typeof input !== 'object' || !WITNESSED.has(input.hook_event_name)) return
  const p = paths()
  const cfg = readConfig()
  const base = {
    v: 1,
    ts: new Date().toISOString(),
    nonce: randomBytes(16).toString('hex'),
    event: input.hook_event_name,
    agent: arg('--agent') || 'unknown',
    session: input.session_id ?? null,
    mode: 'witness',
    version: VERSION,
  }
  try {
    const isTool = input.hook_event_name === 'PreToolUse'
    append(
      p.ledger,
      {
        ...base,
        tool: isTool ? input.tool_name ?? null : null,
        tool_use_id: isTool ? input.tool_use_id ?? null : null,
        transcript_path: input.transcript_path ?? null,
        input_sha256: isTool ? sha256(canonical(input.tool_input ?? {})) : null,
        target: isTool ? targetOf(input) : null,
        subagent: input.agent_id ? { id: input.agent_id, type: input.agent_type ?? null } : undefined,
      },
      { seq: true },
    )
  } catch (err) {
    try {
      append(p.ledger, { ...base, event: 'error', error: String(err?.message || err).slice(0, 300) }, { seq: true })
    } catch {
      /* nothing left to do */
    }
  }
  try {
    maybeFlush({ cfg, always: input.hook_event_name === 'SessionEnd' })
  } catch {
    /* fail open */
  }
}

main()

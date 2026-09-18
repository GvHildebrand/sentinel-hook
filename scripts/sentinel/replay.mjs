#!/usr/bin/env node
/**
 * replay.mjs — run the sentinel's write rules over the repository's entire git history.
 *
 *   node scripts/sentinel/replay.mjs         → research/sentinel/eval/replay.{json,md}
 *
 * For every non-merge commit, attribute it the way the scope gate does (committer identity first,
 * then a declared subject prefix), then evaluate every file it touched against W01 (reserved
 * paths) and W02 (declared scope) under today's inventory. A commit made before the agent was
 * declared is reported separately: the inventory did not exist to enforce yet, so those are the
 * writes an agent made when nothing checked. Person and session commits are counted, with their
 * reserved-path writes, for context only.
 */

import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evaluate } from './rules.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')
const inventory = JSON.parse(readFileSync(path.join(ROOT, '_config', 'agents.json'), 'utf8'))
const git = (...a) => execFileSync('git', ['-C', ROOT, ...a], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })

const agentByEmail = new Map()
for (const [email, who] of Object.entries(inventory._identities ?? {})) {
  if (!email.startsWith('_') && who?.kind === 'agent' && who.agent) agentByEmail.set(email.toLowerCase(), who.agent)
}
for (const a of inventory.agents) {
  if (a.committer_unique === true) for (const e of [a.committer].flat().filter(Boolean)) agentByEmail.set(String(e).toLowerCase(), a.id)
}
const prefixes = []
for (const a of inventory.agents) if (a.commit_prefix) for (const p of String(a.commit_prefix).split('|')) prefixes.push([p.trim(), a.id])
const kindOf = (email) => inventory._identities?.[email]?.kind ?? 'unknown'
const since = Object.fromEntries(inventory.agents.map((a) => [a.id, a.since || null]))

const lines = git('log', '--no-merges', '--format=%H%x1f%ce%x1f%ae%x1f%s%x1f%cI').trim().split('\n')
const commits = []
for (const l of lines) {
  const [sha, ce, ae, subject, date] = l.split('\x1f')
  const files = git('show', '--name-only', '--format=', sha).trim().split('\n').filter(Boolean)
  const committer = ce.toLowerCase()
  let agent = agentByEmail.get(committer) ?? agentByEmail.get(ae.toLowerCase()) ?? null
  let via = agent ? 'identity' : null
  if (!agent) {
    const hit = prefixes.find(([p]) => subject.startsWith(p))
    if (hit) {
      agent = hit[1]
      via = 'prefix'
    }
  }
  commits.push({ sha: sha.slice(0, 7), date: date.slice(0, 10), committer, kind: kindOf(committer), agent, via, subject, files })
}

const perAgent = {}
const people = { commits: 0, files: 0, reserved_writes: [] }
const unconfigured = { commits: 0, files: 0, out_of_declared_union: [] }
const union = [...new Set(inventory.agents.flatMap((a) => a.writes ?? []))]

for (const c of commits) {
  if (c.agent) {
    const identity = { kind: 'agent', agent: c.agent, email: c.committer }
    const bucket = (perAgent[c.agent] ??= { commits: 0, files: 0, before_declaration: { commits: 0, files: 0, denied: [] }, after_declaration: { commits: 0, files: 0, denied: [] }, via: {} })
    bucket.commits++
    bucket.files += c.files.length
    bucket.via[c.via] = (bucket.via[c.via] || 0) + 1
    const phase = since[c.agent] && c.date < since[c.agent] ? bucket.before_declaration : bucket.after_declaration
    phase.commits++
    phase.files += c.files.length
    for (const f of c.files) {
      const v = evaluate({ tool: 'Write', input: { file_path: f }, identity, cwd: ROOT, repoRoot: ROOT, inventory })
      if (v.decision === 'deny') phase.denied.push({ sha: c.sha, date: c.date, file: f, rule: v.rule, via: c.via })
    }
  } else if (c.kind === 'unconfigured') {
    unconfigured.commits++
    unconfigured.files += c.files.length
    for (const f of c.files) if (!union.some((w) => (w.endsWith('/') ? f.startsWith(w) : w.includes('*') ? new RegExp('^' + w.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$').test(f) : f === w))) unconfigured.out_of_declared_union.push({ sha: c.sha, date: c.date, file: f })
  } else {
    people.commits++
    people.files += c.files.length
    const identity = { kind: 'person', agent: null, email: c.committer }
    for (const f of c.files) {
      const v = evaluate({ tool: 'Write', input: { file_path: f }, identity, cwd: ROOT, repoRoot: ROOT, inventory })
      if (v.findings.some((x) => x.rule === 'W01.reserved-path')) people.reserved_writes.push({ sha: c.sha, date: c.date, file: f })
    }
  }
}

const out = { generated: new Date().toISOString(), head: git('rev-parse', '--short', 'HEAD').trim(), commits: commits.length, agents: perAgent, people, unconfigured }
const evalDir = path.join(ROOT, 'research', 'sentinel', 'eval')
mkdirSync(evalDir, { recursive: true })
writeFileSync(path.join(evalDir, 'replay.json'), JSON.stringify(out, null, 2) + '\n')

let md = `# Sentinel — replay over git history\n\nGenerated ${out.generated} at \`${out.head}\` by \`scripts/sentinel/replay.mjs\`: ${out.commits} non-merge commits, every file of every agent-attributed commit evaluated against today's inventory (W01 reserved paths, W02 declared scope).\n\n`
md += `| Agent | Commits | Files | Attributed by | Before declaration: commits / files / would-deny | After declaration: commits / files / would-deny |\n|---|---|---|---|---|---|\n`
for (const [id, b] of Object.entries(perAgent)) {
  md += `| \`${id}\` | ${b.commits} | ${b.files} | ${Object.entries(b.via).map(([k, v]) => `${k} ${v}`).join(', ')} | ${b.before_declaration.commits} / ${b.before_declaration.files} / **${b.before_declaration.denied.length}** | ${b.after_declaration.commits} / ${b.after_declaration.files} / **${b.after_declaration.denied.length}** |\n`
}
md += `| people and live sessions | ${people.commits} | ${people.files} | — | reserved-path writes: ${people.reserved_writes.length} | (allowed; recorded) |\n`
md += `| unconfigured containers | ${unconfigured.commits} | ${unconfigured.files} | — | files outside every declared scope: ${unconfigured.out_of_declared_union.length} | (unattributable) |\n\n`
for (const [id, b] of Object.entries(perAgent)) {
  for (const [phase, label] of [['after_declaration', 'after declaration'], ['before_declaration', 'before declaration']]) {
    const d = b[phase].denied
    if (!d.length) continue
    md += `### \`${id}\` — would have been denied, ${label} (${d.length})\n\n| Commit | Date | File | Rule | Attributed by |\n|---|---|---|---|---|\n`
    for (const x of d.slice(0, 40)) md += `| ${x.sha} | ${x.date} | \`${x.file}\` | ${x.rule} | ${x.via} |\n`
    if (d.length > 40) md += `| … | | ${d.length - 40} more in replay.json | | |\n`
    md += '\n'
  }
}
if (unconfigured.out_of_declared_union.length) {
  md += `### Unconfigured containers — files outside every declared scope (${unconfigured.out_of_declared_union.length})\n\n| Commit | Date | File |\n|---|---|---|\n`
  for (const x of unconfigured.out_of_declared_union.slice(0, 30)) md += `| ${x.sha} | ${x.date} | \`${x.file}\` |\n`
  md += '\n'
}
writeFileSync(path.join(evalDir, 'replay.md'), md)
console.log(md)

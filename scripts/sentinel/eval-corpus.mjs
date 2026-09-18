#!/usr/bin/env node
/**
 * eval-corpus.mjs — run the rules over corpus.json and write the results.
 *
 *   node scripts/sentinel/eval-corpus.mjs            → research/sentinel/eval/corpus.{json,md}
 *
 * Reports, for the agent and person profiles: recall on destructive items (a deny or an ask counts
 * as caught), false positives on benign items, catch rate per variant class, and whether any of
 * the instruction-like payloads changes a decision. No model is involved anywhere.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { evaluate } from './rules.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')
const corpus = JSON.parse(readFileSync(path.join(HERE, 'corpus.json'), 'utf8'))
const inventory = JSON.parse(readFileSync(path.join(ROOT, '_config', 'agents.json'), 'utf8'))

const agent = { kind: 'agent', agent: 'warnings-daily', email: 'warnings-daily@aivigilia.com' }
const person = { kind: 'person', agent: null, email: 'vigilia@vigilia.dev' }
const run = (cmd, identity) => evaluate({ tool: 'Bash', input: { command: cmd }, identity, cwd: ROOT, repoRoot: ROOT, inventory })
const caught = (v) => v.decision === 'deny' || v.decision === 'ask'

const out = { generated: new Date().toISOString(), profiles: {} }
for (const [name, identity] of [['agent', agent], ['person', person]]) {
  const d = corpus.destructive.filter((x) => !(x.agent_only && name === 'person')).map((x) => ({ ...x, v: run(x.cmd, identity) }))
  const b = corpus.benign.filter((x) => !(x.person_only && name === 'agent')).map((x) => ({ ...x, v: run(x.cmd, identity) }))
  const vr = corpus.variants.map((x) => ({ ...x, v: run(x.cmd, identity) }))
  const byClass = {}
  for (const x of vr) {
    byClass[x.class] ??= { total: 0, caught: 0, missed: [] }
    byClass[x.class].total++
    if (caught(x.v)) byClass[x.class].caught++
    else byClass[x.class].missed.push(x.cmd)
  }
  const inj = []
  const targets = d.filter((x) => caught(x.v)).slice(0, 20)
  let flips = 0
  let trials = 0
  for (const t of targets) {
    for (const p of corpus.injections) {
      trials++
      const v = run(t.cmd + ' ' + p, identity)
      if (v.decision !== t.v.decision) {
        flips++
        inj.push({ id: t.id, payload: p, before: t.v.decision, after: v.decision })
      }
    }
  }
  out.profiles[name] = {
    destructive: { total: d.length, caught: d.filter((x) => caught(x.v)).length, deny: d.filter((x) => x.v.decision === 'deny').length, ask: d.filter((x) => x.v.decision === 'ask').length, missed: d.filter((x) => !caught(x.v)).map((x) => ({ id: x.id, cmd: x.cmd, class: x.class })) },
    benign: { total: b.length, false_positives: b.filter((x) => caught(x.v)).map((x) => ({ id: x.id, cmd: x.cmd, decision: x.v.decision, rule: x.v.rule })) },
    variants: { total: vr.length, caught: vr.filter((x) => caught(x.v)).length, by_class: byClass },
    injections: { trials, flips, detail: inj },
    items: d.map((x) => ({ id: x.id, class: x.class, decision: x.v.decision, rule: x.v.rule })),
  }
}

// Held-out set: built after the rules were frozen, from sources not consulted when writing them.
// Scored separately and never used to tune a rule.
import { createHash } from 'node:crypto'
const heldoutPath = path.join(HERE, 'corpus-heldout.json')
let heldout = null
try {
  heldout = JSON.parse(readFileSync(heldoutPath, 'utf8'))
} catch {
  heldout = null
}
if (heldout) {
  const rulesSha = createHash('sha256').update(readFileSync(path.join(HERE, 'rules.mjs'))).digest('hex')
  out.heldout = { rules_frozen_at: heldout.rules_frozen_at, rules_sha256_at_evaluation: rulesSha, sources: heldout.sources, profiles: {} }
  for (const [name, identity] of [['agent', agent], ['person', person]]) {
    const d = heldout.destructive.map((x) => ({ ...x, v: run(x.cmd, identity) }))
    const b = heldout.benign.map((x) => ({ ...x, v: run(x.cmd, identity) }))
    out.heldout.profiles[name] = {
      destructive: { total: d.length, caught: d.filter((x) => caught(x.v)).length, deny: d.filter((x) => x.v.decision === 'deny').length, ask: d.filter((x) => x.v.decision === 'ask').length, missed: d.filter((x) => !caught(x.v)).map((x) => ({ id: x.id, cmd: x.cmd, class: x.class })) },
      benign: { total: b.length, false_positives: b.filter((x) => caught(x.v)).map((x) => ({ id: x.id, cmd: x.cmd, decision: x.v.decision, rule: x.v.rule })) },
      items: d.map((x) => ({ id: x.id, class: x.class, source: x.source, decision: x.v.decision, rule: x.v.rule })),
    }
  }
}

const evalDir = path.join(ROOT, 'research', 'sentinel', 'eval')
mkdirSync(evalDir, { recursive: true })
writeFileSync(path.join(evalDir, 'corpus.json'), JSON.stringify(out, null, 2) + '\n')

const pct = (a, b) => (b ? ((100 * a) / b).toFixed(1) + '%' : '––')
let md = `# Sentinel — corpus evaluation\n\nGenerated ${out.generated} by \`scripts/sentinel/eval-corpus.mjs\` from \`scripts/sentinel/corpus.json\`. A deny or an ask counts as caught.\n\n`
for (const [name, p] of Object.entries(out.profiles)) {
  md += `## Profile: ${name}\n\n| Set | Items | Caught | Rate |\n|---|---|---|---|\n`
  md += `| Destructive (incident-derived) | ${p.destructive.total} | ${p.destructive.caught} (${p.destructive.deny} deny, ${p.destructive.ask} ask) | ${pct(p.destructive.caught, p.destructive.total)} |\n`
  md += `| Benign look-alikes | ${p.benign.total} | ${p.benign.false_positives.length} false positives | ${pct(p.benign.false_positives.length, p.benign.total)} FPR |\n`
  md += `| Variants (normalisation classes) | ${p.variants.total} | ${p.variants.caught} | ${pct(p.variants.caught, p.variants.total)} |\n`
  md += `| Instruction payloads appended | ${p.injections.trials} trials | ${p.injections.flips} decisions changed | ${pct(p.injections.flips, p.injections.trials)} |\n\n`
  if (p.destructive.missed.length) md += `Missed destructive items: ${p.destructive.missed.map((m) => `${m.id} (${m.class})`).join(', ')}.\n\n`
  if (p.benign.false_positives.length) md += `False positives: ${p.benign.false_positives.map((m) => `${m.id} \`${m.cmd}\` → ${m.decision} by ${m.rule}`).join('; ')}.\n\n`
  md += `### Variant classes\n\n| Class | Items | Caught | Missed |\n|---|---|---|---|\n`
  for (const [cls, r] of Object.entries(p.variants.by_class)) md += `| ${cls} | ${r.total} | ${r.caught} | ${r.missed.map((m) => '`' + m.replace(/\|/g, '\\|') + '`').join('<br>') || '––'} |\n`
  md += '\n'
}
if (out.heldout) {
  md += `# Held-out set\n\nBuilt after the rules were frozen at \`${out.heldout.rules_frozen_at}\` from sources not consulted when the rules were written (${out.heldout.sources.join(', ')}). rules.mjs sha256 at evaluation: \`${out.heldout.rules_sha256_at_evaluation}\`. Never used to tune a rule.\n\n`
  for (const [name, p] of Object.entries(out.heldout.profiles)) {
    md += `## Held-out, profile: ${name}\n\n| Set | Items | Caught | Rate |\n|---|---|---|---|\n`
    md += `| Destructive (held-out) | ${p.destructive.total} | ${p.destructive.caught} (${p.destructive.deny} deny, ${p.destructive.ask} ask) | ${pct(p.destructive.caught, p.destructive.total)} |\n`
    md += `| Benign (held-out) | ${p.benign.total} | ${p.benign.false_positives.length} false positives | ${pct(p.benign.false_positives.length, p.benign.total)} FPR |\n\n`
    if (p.destructive.missed.length) md += `Missed: ${p.destructive.missed.map((m) => `${m.id} (${m.class})`).join('; ')}.\n\n`
    if (p.benign.false_positives.length) md += `False positives: ${p.benign.false_positives.map((m) => `${m.id} \`${m.cmd}\` → ${m.decision} by ${m.rule}`).join('; ')}.\n\n`
    md += `| Item | Class | Decision | Rule |\n|---|---|---|---|\n`
    for (const it of p.items) md += `| ${it.id} | ${it.class} | ${it.decision} | ${it.rule || '––'} |\n`
    md += '\n'
  }
}
writeFileSync(path.join(evalDir, 'corpus.md'), md)
console.log(md)

#!/usr/bin/env node
/**
 * figures.mjs — draw the paper's figures as SVG from the evaluation files and the incident table.
 *
 *   node scripts/sentinel/figures.mjs   → paper/figures/*.svg
 *
 * White ground, black type, one red. No library.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..', '..')
const OUT = path.join(ROOT, 'paper', 'figures')
mkdirSync(OUT, { recursive: true })

const RED = '#9E2B25'
const INK = '#000'
const G1 = '#F4F4F4'
const G2 = '#E5E5E5'
const G3 = '#B3B3B3'
const G4 = '#767676'
const SANS = "'Space Grotesk', Helvetica, Arial, sans-serif"
const MONO = "'Space Mono', Menlo, Consolas, monospace"
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const svg = (w, h, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" font-family="${SANS}" font-size="12" fill="${INK}">\n<rect width="${w}" height="${h}" fill="#fff"/>\n${body}\n</svg>\n`
const mono = (x, y, t, extra = '') => `<text x="${x}" y="${y}" font-family="${MONO}" font-size="10" ${extra}>${esc(t)}</text>`
const text = (x, y, t, extra = '') => `<text x="${x}" y="${y}" ${extra}>${esc(t)}</text>`

// ---------------------------------------------------------------------------------------------
// Figure 1 — the landscape: blocks before the action × reports beyond the operator
// ---------------------------------------------------------------------------------------------
{
  const pts = [
    ['Hook vendors (Zenity, HiddenLayer, Cisco)', 2, 0, -6, 14],
    ['Platform policy (Managed Agents, AgentCore)', 2, 0, -6, 28],
    ['Guard agents (Progent, AgentSpec, ShieldAgent)', 2, 0, -6, 42],
    ['AI-control protocols (trusted monitoring)', 2, 0, -6, 56],
    ['Identity handshakes (A2A, Web Bot Auth)', 0, 0, 8, -8],
    ['Observability (Datadog, Langfuse)', 0, 0, 8, 6],
    ['Kernel observer (AgentSight)', 0, 0, 8, 20],
    ['Gossip / reputation research', 0, 1, 8, 4],
    ['Public thread (AI Village)', 0, 2, 8, 4],
    ["Vigilia's post-push tripwire (2026-09-13)", 0, 2, 8, 18],
    ['Fleet measurement (Anthropic, 2026-09-17)', 0, 1, 8, 18],
    ['Sentinel (this paper)', 2, 2, -6, -10],
  ]
  const W = 720
  const H = 440
  const x0 = 70
  const y0 = 30
  const pw = 560
  const ph = 330
  const X = (v) => x0 + (v / 2) * pw
  const Y = (v) => y0 + ph - (v / 2) * ph
  let b = ''
  b += `<rect x="${X(1)}" y="${y0}" width="${pw / 2}" height="${ph / 2}" fill="${G1}"/>`
  b += mono(X(1) + 8, y0 + 14, 'The empty quadrant, until now', `fill="${G4}"`)
  b += `<rect x="${x0}" y="${y0}" width="${pw}" height="${ph}" fill="none" stroke="${INK}" stroke-width="1"/>`
  b += `<line x1="${X(1)}" y1="${y0}" x2="${X(1)}" y2="${y0 + ph}" stroke="${G2}"/><line x1="${x0}" y1="${Y(1)}" x2="${x0 + pw}" y2="${Y(1)}" stroke="${G2}"/>`
  b += mono(x0 + pw / 2, y0 + ph + 34, 'Blocks the action before it runs →', 'text-anchor="middle"')
  b += mono(-(y0 + ph / 2), x0 - 44, 'Reports beyond the operator →', `text-anchor="middle" transform="rotate(-90)"`)
  for (const [l, v] of [['no', 0], ['partly', 1], ['yes', 2]]) {
    b += mono(X(v), y0 + ph + 16, l, 'text-anchor="middle"')
    b += mono(x0 - 8, Y(v) + 4, l, 'text-anchor="end"')
  }
  for (const [label, x, y, dx, dy] of pts) {
    const isUs = label.startsWith('Sentinel')
    const cx = X(x) + (x === 2 ? -22 : 22)
    const cy = Y(y) + (y === 2 ? 22 : y === 0 ? -22 : 0)
    b += `<circle cx="${cx}" cy="${cy}" r="${isUs ? 7 : 5}" fill="${isUs ? RED : INK}"/>`
    b += text(cx + dx, cy + dy, label, `font-size="11" ${dx < 0 ? 'text-anchor="end"' : ''} ${isUs ? `fill="${RED}" font-weight="600"` : ''}`)
  }
  writeFileSync(path.join(OUT, 'landscape.svg'), svg(W, H, b))
}

// ---------------------------------------------------------------------------------------------
// Figure 2 — sixteen incidents: who noticed, and how long it took
// ---------------------------------------------------------------------------------------------
{
  // minutes to detection (order of magnitude, from the cited reports) and the class of first detector
  const rows = [
    ['2025-07', 'Amazon Q wiper prompt', 1440, 'outsider'],
    ['2025-07', 'Replit production tables', 480, 'human'],
    ['2025-07', 'Gemini CLI file loss', 5, 'human'],
    ['2025-08', 'Nx s1ngularity', 240, 'outsider'],
    ['2025-10', 'Claude Code home wipes', 5, 'human'],
    ['2025-12', 'Antigravity drive wipe', 5, 'human'],
    ['2025-12', 'Kiro environment recreate', 1, 'operator'],
    ['2026-01', 'Cowork photo deletion', 180, 'human'],
    ['2026-02', 'OpenClaw message flood', 5, 'human'],
    ['2026-02', 'OpenClaw mailbox purge', 1, 'human'],
    ['2026-03', 'Vercel wrong-repo deploy', 180, 'human'],
    ['2026-03', 'Meta forum advice', 120, 'operator'],
    ['2026-04', 'PocketOS volume deletion', 1, 'human'],
    ['2026-05', 'Codex host /etc mount', 180, 'human'],
    ['2026-07', 'Hugging Face intrusion', 2880, 'operator'],
    ['2026-09', 'Outreach agent spam', 4320, 'outsider'],
  ]
  const W = 720
  const H = 30 + rows.length * 22 + 60
  const x0 = 250
  const pw = 420
  const lg = (m) => Math.log10(m)
  const X = (m) => x0 + (lg(m) / lg(10000)) * pw
  const col = { human: INK, operator: G3, outsider: RED }
  let b = ''
  for (const [t, m] of [['1 min', 1], ['10', 10], ['1 h', 60], ['1 day', 1440], ['1 week', 10000]]) {
    b += `<line x1="${X(m)}" y1="24" x2="${X(m)}" y2="${H - 50}" stroke="${G2}"/>` + mono(X(m), H - 36, t, 'text-anchor="middle"')
  }
  rows.forEach(([d, name, m, who], i) => {
    const y = 40 + i * 22
    b += mono(12, y + 4, d, `fill="${G4}"`)
    b += text(70, y + 4, name, 'font-size="11"')
    b += `<line x1="${x0}" y1="${y}" x2="${X(m)}" y2="${y}" stroke="${G2}"/><circle cx="${X(m)}" cy="${y}" r="5" fill="${col[who]}"/>`
  })
  const ly = H - 12
  b += `<circle cx="${x0}" cy="${ly}" r="5" fill="${INK}"/>` + mono(x0 + 10, ly + 4, 'the harmed person, watching')
  b += `<circle cx="${x0 + 190}" cy="${ly}" r="5" fill="${G3}"/>` + mono(x0 + 200, ly + 4, "the operator's own telemetry")
  b += `<circle cx="${x0 + 380}" cy="${ly}" r="5" fill="${RED}"/>` + mono(x0 + 390, ly + 4, 'an outsider')
  b += mono(x0 + pw / 2, 14, 'Time from the rogue action to its detection (log scale)', 'text-anchor="middle"')
  writeFileSync(path.join(OUT, 'incidents.svg'), svg(W, H, b))
}

// ---------------------------------------------------------------------------------------------
// Figure 3 — architecture
// ---------------------------------------------------------------------------------------------
{
  const W = 720
  const H = 300
  const box = (x, y, w, h, title, sub, fill = '#fff') =>
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}" stroke="${INK}"/>` +
    text(x + 10, y + 20, title, `font-weight="600" ${fill === INK ? 'fill="#fff"' : ''}`) +
    (sub ? mono(x + 10, y + 38, sub, `fill="${fill === INK ? '#fff' : G4}"`) : '')
  const arrow = (x1, y1, x2, y2, label) =>
    `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${INK}" marker-end="url(#a)"/>` + (label ? mono((x1 + x2) / 2, (y1 + y2) / 2 - 6, label, `text-anchor="middle" fill="${G4}"`) : '')
  let b = `<defs><marker id="a" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${INK}"/></marker></defs>`
  b += box(20, 30, 150, 50, 'Agent session', 'Claude Code · subagents')
  b += box(230, 30, 170, 50, 'Sentinel hook', 'PreToolUse · SessionStart')
  b += box(460, 30, 150, 50, 'Rules', 'deterministic, 24 rule ids')
  b += arrow(170, 55, 230, 55, 'every call')
  b += arrow(400, 55, 460, 55, '')
  b += arrow(460, 70, 400, 70, '')
  b += mono(430, 84, 'allow · ask · deny', `text-anchor="middle" fill="${RED}"`)
  b += box(230, 120, 170, 50, 'Ledger', 'hash chain, one file per identity')
  b += arrow(315, 80, 315, 120, 'record + heartbeat')
  b += box(20, 120, 150, 50, "The agent's commit", 'git push')
  b += arrow(230, 145, 170, 145, '')
  b += box(20, 210, 150, 50, 'sentinel attest', 'GitHub Actions')
  b += arrow(95, 170, 95, 210, 'on push')
  b += box(230, 210, 170, 50, 'Sigstore Rekor', 'public transparency log', INK)
  b += box(460, 210, 150, 50, 'RFC 3161 TSA', 'independent authority', INK)
  b += arrow(170, 235, 230, 235, 'sign-blob')
  b += arrow(400, 235, 460, 235, 'timestamp')
  b += mono(360, 290, 'Two clocks, neither owned by the operator or by Vigilia. The attestation is committed back under its own identity.', `text-anchor="middle" fill="${G4}"`)
  writeFileSync(path.join(OUT, 'architecture.svg'), svg(W, H, b))
}

// ---------------------------------------------------------------------------------------------
// Figure 4 — replay over git history
// ---------------------------------------------------------------------------------------------
{
  const r = JSON.parse(readFileSync(path.join(ROOT, 'research', 'sentinel', 'eval', 'replay.json'), 'utf8'))
  const agents = Object.entries(r.agents)
  const W = 720
  const rowH = 44
  const H = 60 + agents.length * rowH + 40
  const x0 = 200
  const pw = 480
  const max = Math.max(...agents.map(([, a]) => a.files))
  const X = (v) => x0 + (v / max) * pw
  let b = mono(x0 + pw / 2, 16, `Files written per agent across ${r.commits} commits — and how many the sentinel would have denied`, 'text-anchor="middle"')
  agents.forEach(([id, a], i) => {
    const y = 40 + i * rowH
    b += mono(12, y + 14, id)
    b += mono(12, y + 28, `${a.commits} commits`, `fill="${G4}"`)
    const before = a.before_declaration
    const after = a.after_declaration
    b += `<rect x="${x0}" y="${y}" width="${X(after.files) - x0}" height="12" fill="${INK}"/>`
    b += `<rect x="${x0}" y="${y + 14}" width="${X(before.files) - x0}" height="12" fill="${G3}"/>`
    if (after.denied.length) b += `<rect x="${x0}" y="${y}" width="${Math.max(2, X(after.denied.length) - x0)}" height="12" fill="${RED}"/>`
    if (before.denied.length) b += `<rect x="${x0}" y="${y + 14}" width="${Math.max(2, X(before.denied.length) - x0)}" height="12" fill="${RED}"/>`
    b += mono(X(after.files) + 6, y + 10, `${after.files} after declaration · ${after.denied.length} would-deny`, `fill="${G4}"`)
    b += mono(X(before.files) + 6, y + 24, `${before.files} before · ${before.denied.length} would-deny`, `fill="${G4}"`)
  })
  const ly = H - 12
  b += `<rect x="${x0}" y="${ly - 8}" width="12" height="10" fill="${INK}"/>` + mono(x0 + 18, ly, 'after the agent was declared')
  b += `<rect x="${x0 + 220}" y="${ly - 8}" width="12" height="10" fill="${G3}"/>` + mono(x0 + 238, ly, 'before')
  b += `<rect x="${x0 + 320}" y="${ly - 8}" width="12" height="10" fill="${RED}"/>` + mono(x0 + 338, ly, 'would have been denied')
  writeFileSync(path.join(OUT, 'replay.svg'), svg(W, H, b))
}

// ---------------------------------------------------------------------------------------------
// Figure 5 — the corpus
// ---------------------------------------------------------------------------------------------
{
  const c = JSON.parse(readFileSync(path.join(ROOT, 'research', 'sentinel', 'eval', 'corpus.json'), 'utf8'))
  const p = c.profiles.agent
  const classes = Object.entries(p.variants.by_class)
  const W = 720
  const H = 120 + classes.length * 16 + 40
  let b = mono(12, 16, 'Agent profile — incident-derived corpus')
  const bar = (y, label, n, k, note) => {
    const pw = 300
    const x0 = 250
    b += text(12, y + 11, label, 'font-size="11"')
    b += `<rect x="${x0}" y="${y}" width="${pw}" height="12" fill="${G2}"/><rect x="${x0}" y="${y}" width="${(k / n) * pw}" height="12" fill="${INK}"/>`
    b += mono(x0 + pw + 8, y + 10, `${k} / ${n}${note ? ' · ' + note : ''}`)
  }
  bar(30, 'Destructive commands caught', p.destructive.total, p.destructive.caught, `${p.destructive.deny} denied`)
  bar(50, 'Benign look-alikes wrongly caught', p.benign.total, p.benign.false_positives.length, 'false positives')
  bar(70, 'Variant forms caught', p.variants.total, p.variants.caught)
  bar(90, 'Decisions changed by instruction payloads', p.injections.trials, p.injections.flips)
  b += mono(12, 124, 'Variant classes (caught / items)', `fill="${G4}"`)
  classes.forEach(([cls, r], i) => {
    const y = 136 + i * 16
    const miss = r.caught < r.total
    b += `<rect x="12" y="${y - 9}" width="10" height="10" fill="${miss ? RED : INK}"/>`
    b += mono(30, y, `${r.caught}/${r.total}  ${cls}${miss ? '  — missed: ' + r.missed.join(' ; ') : ''}`, miss ? `fill="${RED}"` : '')
  })
  writeFileSync(path.join(OUT, 'corpus.svg'), svg(W, H, b))
}

console.log('figures written to', path.relative(ROOT, OUT))

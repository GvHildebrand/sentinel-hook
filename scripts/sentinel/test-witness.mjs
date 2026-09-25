// node --test scripts/sentinel/test-witness.mjs — 0.4.0: the witness never decides, the ledger
// survives concurrent writers, and the installer edits a settings file the way a guest should.
import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, statSync, utimesSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'
import { append, verify } from './ledger.mjs'
import { evaluate } from './rules.mjs'
import { GATE_MATCHER, addOurHooks, backupsOf, detectAgents, init, removeOurHooks, uninstall } from './install.mjs'
import { categoryForRule } from './witness-client.mjs'
import { CLI, GATE_HOOK, HERE, ROOT, WITNESS_HOOK, hookEnv, pool, runAsync, runSync, tempDir } from './test-helpers.mjs'

// ---------------------------------------------------------------------------------------------
// The witness never decides
// ---------------------------------------------------------------------------------------------

function importGraph(entry) {
  const seen = new Set()
  const walk = (f) => {
    if (seen.has(f)) return
    seen.add(f)
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/(?:from\s+|import\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g)) walk(path.resolve(path.dirname(f), m[1]))
  }
  walk(entry)
  return [...seen]
}

test('structure: the witness entry point cannot reach rules.mjs, a decision, or stdout', () => {
  const graph = importGraph(WITNESS_HOOK)
  assert.ok(graph.length >= 3)
  assert.ok(!graph.some((f) => path.basename(f) === 'rules.mjs'), `witness imports: ${graph.map((f) => path.basename(f)).join(', ')}`)
  assert.ok(!graph.some((f) => path.basename(f) === 'sentinel.mjs'))
  for (const f of graph) {
    const src = readFileSync(f, 'utf8').replace(/\/\*\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    for (const banned of ['permissionDecision', 'hookSpecificOutput', 'process.stdout', 'console.', 'evaluate(', 'additionalContext']) {
      assert.ok(!src.includes(banned), `${path.basename(f)} contains ${banned}`)
    }
  }
})

function corpusCommands() {
  const sets = []
  for (const f of [path.join(ROOT, 'eval', 'corpus.json'), path.join(HERE, 'corpus.json'), path.join(HERE, 'corpus-heldout.json')]) {
    if (!existsSync(f)) continue
    const j = JSON.parse(readFileSync(f, 'utf8'))
    for (const k of ['destructive', 'benign', 'variants']) for (const x of j[k] || []) if (x?.cmd) sets.push({ id: x.id || x.of, cmd: x.cmd, destructive: k !== 'benign' })
  }
  return sets
}

test('every corpus command through the witness hook: empty stdout, exit 0; the gate still decides as before', async () => {
  const items = corpusCommands()
  assert.ok(items.length >= 150, `corpus has ${items.length} commands`)
  const home = tempDir('witness-home-')
  const cwd = tempDir('witness-cwd-')
  const hook = (cmd, i) => JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'corpus', cwd, tool_name: 'Bash', tool_input: { command: cmd }, tool_use_id: `t${i}` })
  const witness = await pool(items, 8, (x, i) => runAsync(WITNESS_HOOK, ['--agent', 'claude-code'], { home, cwd, input: hook(x.cmd, i) }))
  witness.forEach((r, i) => {
    assert.equal(r.stdout, '', `witness printed for ${items[i].id}: ${r.stdout}`)
    assert.equal(r.status, 0, items[i].id)
  })
  const v = verify(path.join(home, '.vigilia', 'ledger', 'witness.jsonl'))
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.equal(v.lines, items.length)

  // The gate, installed form, same commands. Its decision must equal the rules' decision, unchanged.
  const gateHome = tempDir('gate-home-')
  const gate = await pool(items, 8, (x, i) => runAsync(GATE_HOOK, ['--agent', 'claude-code'], { home: gateHome, cwd, input: hook(x.cmd, i) }))
  const person = { kind: 'person', agent: null, email: null, via: 'none' }
  let caught = 0
  gate.forEach((r, i) => {
    const expected = evaluate({ tool: 'Bash', input: { command: items[i].cmd }, identity: person, cwd, repoRoot: ROOT, inventory: null }).decision
    const got = r.stdout ? JSON.parse(r.stdout).hookSpecificOutput.permissionDecision : 'allow'
    assert.equal(got, expected, `${items[i].id}: ${items[i].cmd}`)
    if (items[i].destructive && got !== 'allow') caught++
  })
  assert.ok(caught >= 60, `the gate caught ${caught} destructive commands`)
  assert.equal(verify(path.join(gateHome, '.vigilia', 'ledger', 'witness.jsonl')).ok, true)
})

test('witness: other events and tools are recorded silently, and a line binds to its transcript entry', () => {
  const home = tempDir('witness-home-')
  const events = [
    { hook_event_name: 'SessionStart', session_id: 's', transcript_path: '/t/s.jsonl', source: 'startup' },
    { hook_event_name: 'SubagentStart', session_id: 's', agent_id: 'a1', agent_type: 'Explore' },
    { hook_event_name: 'PreToolUse', session_id: 's', transcript_path: '/t/s.jsonl', tool_name: 'Write', tool_input: { file_path: '/p/x.ts', content: 'secret body' }, tool_use_id: 'toolu_1' },
    { hook_event_name: 'PreToolUse', session_id: 's', tool_name: 'mcp__x__y', tool_input: { q: 1 }, tool_use_id: 'toolu_2' },
    { hook_event_name: 'PostToolUse', session_id: 's', tool_name: 'Bash', tool_input: {} },
    { hook_event_name: 'SessionEnd', session_id: 's', reason: 'other' },
  ]
  for (const e of events) {
    const r = runSync(WITNESS_HOOK, ['--agent', 'claude-code'], { home, input: JSON.stringify(e) })
    assert.equal(r.stdout, '')
    assert.equal(r.status, 0)
  }
  assert.equal(runSync(WITNESS_HOOK, [], { home, input: 'not json' }).stdout, '')
  const lines = readFileSync(path.join(home, '.vigilia', 'ledger', 'witness.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  assert.deepEqual(lines.map((l) => l.event), ['SessionStart', 'SubagentStart', 'PreToolUse', 'PreToolUse', 'SessionEnd']) // PostToolUse is not witnessed
  const w = lines[2]
  for (const k of ['v', 'ts', 'seq', 'nonce', 'event', 'agent', 'session', 'tool', 'tool_use_id', 'transcript_path', 'input_sha256', 'target', 'prev', 'hash']) assert.ok(k in w, k)
  assert.equal(w.seq, 3)
  assert.equal(w.agent, 'claude-code')
  assert.equal(w.tool_use_id, 'toolu_1')
  assert.match(w.nonce, /^[0-9a-f]{32}$/)
  assert.ok(!JSON.stringify(lines).includes('secret body'), 'file content is never written, only its hash')
  assert.equal(lines[1].subagent.type, 'Explore')
  // No config (never installed) means no network and no flusher.
  assert.equal(existsSync(path.join(home, '.vigilia', 'flush.stamp')), false)
})

// ---------------------------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------------------------

test('concurrency: 8 processes x 25 appends to one chain, and it still verifies', async () => {
  const dir = tempDir('ledger-conc-')
  const file = path.join(dir, 'witness.jsonl')
  const code = `import { append } from ${JSON.stringify(path.join(HERE, 'ledger.mjs'))}; for (let i = 0; i < 25; i++) append(${JSON.stringify(file)}, { v: 1, w: process.argv[1], i }, { seq: true })`
  const { spawn } = await import('node:child_process')
  await Promise.all(Array.from({ length: 8 }, (_, k) => new Promise((resolve, reject) => {
    const c = spawn(process.execPath, ['--input-type=module', '-e', code, String(k)], { stdio: 'ignore', env: hookEnv(dir) })
    c.on('close', (s) => (s === 0 ? resolve() : reject(new Error('writer failed'))))
  })))
  const v = verify(file)
  assert.equal(v.ok, true, JSON.stringify(v))
  assert.equal(v.lines, 200)
  const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  assert.deepEqual(lines.map((l) => l.seq), Array.from({ length: 200 }, (_, i) => i + 1))
  assert.ok(!lines.some((l) => l.lock === false))
})

test('lock: a stale lock is cleaned up; a live one that cannot be taken fails open with lock:false', () => {
  const dir = tempDir('ledger-lock-')
  const file = path.join(dir, 'x.jsonl')
  append(file, { v: 1 }, { seq: true })
  writeFileSync(file + '.lock', '')
  const old = new Date(Date.now() - 60_000)
  utimesSync(file + '.lock', old, old)
  const a = append(file, { v: 1 }, { seq: true })
  assert.equal(a.lock, undefined)
  assert.equal(existsSync(file + '.lock'), false)
  writeFileSync(file + '.lock', '') // fresh: another writer holds it
  const t0 = Date.now()
  const b = append(file, { v: 1 }, { seq: true, waitMs: 150 })
  assert.ok(Date.now() - t0 < 1000)
  assert.equal(b.lock, false)
  assert.equal(b.seq, 3)
  assert.equal(verify(file).ok, true)
})

test('verify: a gap in seq breaks the chain', () => {
  const dir = tempDir('ledger-seq-')
  const file = path.join(dir, 'x.jsonl')
  append(file, { v: 1 }, { seq: true })
  append(file, { v: 1, seq: 9 }) // a line claiming the wrong position
  assert.equal(verify(file).why, 'seq mismatch')
})

// ---------------------------------------------------------------------------------------------
// Near-miss categories
// ---------------------------------------------------------------------------------------------

test('near-miss categories from rule ids', () => {
  assert.equal(categoryForRule('B01.rm-recursive-catastrophic'), 'destructive_command')
  assert.equal(categoryForRule('B09.infrastructure-destruction'), 'destructive_command')
  assert.equal(categoryForRule('B07.git-history-or-remote-destruction', 'git push --force origin main'), 'unreviewed_push')
  assert.equal(categoryForRule('B07.git-history-or-remote-destruction', 'git reset --hard HEAD~3'), 'destructive_command')
  assert.equal(categoryForRule('B14.credential-read'), 'credential_exposure')
  assert.equal(categoryForRule('W03.credential-file-write'), 'credential_exposure')
  assert.equal(categoryForRule('B10.remote-code-execution'), 'injection_suspected')
  assert.equal(categoryForRule('W06.agent-self-write'), 'injection_suspected')
  assert.equal(categoryForRule('E02.egress-not-allowlisted'), 'other')
  assert.equal(categoryForRule('W02.out-of-scope'), 'other')
})

// ---------------------------------------------------------------------------------------------
// Installer
// ---------------------------------------------------------------------------------------------

const USER_SETTINGS = {
  permissions: { allow: ['Bash(npm test)'] },
  hooks: {
    PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo user-hook' }] }],
    Stop: [{ hooks: [{ type: 'command', command: 'say done' }] }],
  },
}

function seededHome() {
  const home = tempDir('init-home-')
  mkdirSync(path.join(home, '.claude'))
  writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify(USER_SETTINGS, null, 4) + '\n')
  return home
}
const settingsOf = (home) => JSON.parse(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'))
const ourCommands = (s) => JSON.stringify(s).match(/\.vigilia\/sentinel-hook\//g)?.length ?? 0

test('init: backs up, appends after the user\'s hooks, keeps formatting, generates the key locally', () => {
  const home = seededHome()
  const env = hookEnv(home)
  const r = init({ env, cwd: home })
  assert.equal(r.ok, true, r.error)
  const s = settingsOf(home)
  assert.deepEqual(s.permissions, USER_SETTINGS.permissions)
  assert.equal(s.hooks.PreToolUse[0].hooks[0].command, 'echo user-hook') // the user's hook stays first
  assert.equal(s.hooks.PreToolUse[1].matcher, '*')
  assert.match(s.hooks.PreToolUse[1].hooks[0].command, /witness\.mjs" --agent claude-code$/)
  assert.deepEqual(Object.keys(s.hooks).sort(), ['PreToolUse', 'SessionEnd', 'SessionStart', 'Stop', 'SubagentStart'])
  assert.deepEqual(s.hooks.Stop, USER_SETTINGS.hooks.Stop)
  assert.equal(ourCommands(s), 4)
  assert.match(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'), /\n {4}"permissions"/)
  const backups = backupsOf(path.join(home, '.claude', 'settings.json'))
  assert.equal(backups.length, 1)
  assert.deepEqual(JSON.parse(readFileSync(backups[0], 'utf8')), USER_SETTINGS)
  // key: local, private
  const keyFile = path.join(home, '.vigilia', 'keys', 'ed25519.pem')
  assert.equal(statSync(keyFile).mode & 0o777, 0o600)
  assert.equal(statSync(path.dirname(keyFile)).mode & 0o777, 0o700)
  assert.match(r.installId, /^[0-9a-f]{32}$/)
  // runtime: copied, with a `current` pointer the hooks use
  const cur = path.join(home, '.vigilia', 'sentinel-hook', 'current')
  assert.ok(lstatSync(cur).isSymbolicLink())
  assert.equal(readlinkSync(cur), '0.4.0')
  assert.ok(existsSync(path.join(cur, 'scripts', 'sentinel', 'witness.mjs')))
  assert.ok(s.hooks.SessionStart[0].hooks[0].command.includes(cur))
  const cfg = JSON.parse(readFileSync(path.join(home, '.vigilia', 'config.json'), 'utf8'))
  assert.equal(cfg.mode, 'witness')
  assert.equal(cfg.share_near_misses, false)
  assert.equal(cfg.witness_url, 'https://witness.aivigilia.com')
  assert.deepEqual(cfg.agents, ['claude-code'])
})

test('init is idempotent; --gate swaps our entries in place; uninstall removes only ours', () => {
  const home = seededHome()
  const env = hookEnv(home)
  const file = path.join(home, '.claude', 'settings.json')
  init({ env, cwd: home })
  const once = readFileSync(file, 'utf8')
  const again = init({ env, cwd: home })
  assert.equal(again.changed, false)
  assert.equal(readFileSync(file, 'utf8'), once)
  assert.equal(backupsOf(file).length, 1, 'no backup when nothing changes')
  const g = init({ env, cwd: home, gate: true })
  assert.equal(g.changed, true)
  const s = settingsOf(home)
  assert.equal(ourCommands(s), 4)
  assert.equal(s.hooks.PreToolUse[1].matcher, GATE_MATCHER)
  assert.match(s.hooks.PreToolUse[1].hooks[0].command, /sentinel\.mjs" --agent claude-code$/)
  const u = uninstall({ env, cwd: home })
  assert.equal(u.removed.length, 1)
  assert.deepEqual(settingsOf(home), USER_SETTINGS)
  assert.equal(uninstall({ env, cwd: home }).removed.length, 0) // idempotent
  assert.ok(existsSync(path.join(home, '.vigilia', 'keys', 'ed25519.pem')), 'uninstall leaves the key')
})

test('init refuses a settings file that is not valid JSON, and changes nothing', () => {
  const home = tempDir('init-bad-')
  mkdirSync(path.join(home, '.claude'))
  const bad = '{ "hooks": { , }\n'
  writeFileSync(path.join(home, '.claude', 'settings.json'), bad)
  const r = init({ env: hookEnv(home), cwd: home })
  assert.equal(r.ok, false)
  assert.equal(r.code, 2)
  assert.match(r.error, /not valid JSON/)
  assert.equal(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'), bad)
  assert.equal(existsSync(path.join(home, '.vigilia')), false)
  const cli = runSync(CLI, ['init', '--yes'], { home })
  assert.equal(cli.status, 2)
  assert.match(cli.stderr, /not valid JSON/)
})

test('init --dry-run writes nothing; no Claude Code means nothing is installed', () => {
  const home = seededHome()
  const before = readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')
  const r = runSync(CLI, ['init', '--dry-run'], { home })
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /Dry run/)
  assert.equal(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'), before)
  assert.equal(existsSync(path.join(home, '.vigilia')), false)
  const empty = tempDir('init-none-')
  const none = init({ env: hookEnv(empty, { PATH: '' }), cwd: empty })
  assert.equal(none.ok, false)
  assert.equal(none.code, 1)
  assert.equal(existsSync(path.join(empty, '.vigilia')), false)
})

test('init --project writes the repository settings, not the user\'s', () => {
  const home = seededHome()
  const repo = tempDir('init-repo-')
  const r = init({ env: hookEnv(home), cwd: repo, project: true })
  assert.equal(r.ok, true)
  assert.equal(ourCommands(JSON.parse(readFileSync(path.join(repo, '.claude', 'settings.json'), 'utf8'))), 4)
  assert.deepEqual(settingsOf(home), USER_SETTINGS)
  const u = uninstall({ env: hookEnv(home), cwd: tempDir('elsewhere-') })
  assert.equal(u.removed.length, 1, 'uninstall finds the project file through the config')
})

test('Cursor and Codex are detected and named, never hooked', () => {
  const home = seededHome()
  mkdirSync(path.join(home, '.cursor'))
  mkdirSync(path.join(home, '.codex'))
  const d = detectAgents(hookEnv(home, { PATH: '' }))
  assert.deepEqual(d, { 'claude-code': true, cursor: true, codex: true })
  const r = runSync(CLI, ['init', '--yes', '--offline'], { home })
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /Cursor and Codex detected — not yet supported by the witness; Claude Code only in 0\.4\.0\./)
  assert.equal(existsSync(path.join(home, '.cursor', 'hooks.json')), false)
  assert.equal(existsSync(path.join(home, '.codex', 'hooks.json')), false)
})

test('CLI init output: at most six lines, says what is and is not sent, receipt and privacy URLs, gate warning', () => {
  const home = seededHome()
  const r = runSync(CLI, ['init', '--yes'], { home, env: hookEnv(home, { PATH: path.dirname(process.execPath) }) })
  assert.equal(r.status, 0, r.stderr)
  const lines = r.stdout.trim().split('\n')
  assert.ok(lines.length <= 6, r.stdout)
  assert.match(r.stdout, /a fingerprint of the record, a count, a timestamp and a signature/)
  assert.match(r.stdout, /Never sent: code, commands, prompts, file paths, repo names/)
  assert.match(r.stdout, /https:\/\/witness\.aivigilia\.com\/r\/[0-9a-f]{32}/)
  assert.match(r.stdout, /https:\/\/aivigilia\.com\/witness\/privacy/)
  assert.ok(!/block/.test(r.stdout))
  const g = runSync(CLI, ['init', '--yes', '--gate'], { home, env: hookEnv(home, { PATH: path.dirname(process.execPath) }) })
  assert.ok(g.stdout.trim().split('\n').length <= 6)
  assert.match(g.stdout, /can block real work/)
  const st = runSync(CLI, ['status'], { home })
  assert.match(st.stdout, /Mode: gate/)
  assert.match(st.stdout, /chain verified/)
  const un = runSync(CLI, ['uninstall'], { home })
  assert.equal(un.status, 0)
  assert.match(un.stdout, /rm -rf ~\/\.vigilia/)
  assert.deepEqual(settingsOf(home), USER_SETTINGS)
})

test('package: every runtime file the installer copies is in the npm files list, and nothing else is', async () => {
  const { RUNTIME_FILES } = await import('./install.mjs')
  const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
  for (const f of RUNTIME_FILES) if (!['package.json', 'LICENSE'].includes(f)) assert.ok(pkg.files.includes(f), f)
  assert.ok(!pkg.files.some((f) => /\/test[-.]|^eval\/|^paper\/|corpus|witness-server|^research\//.test(f)), pkg.files.join(', '))
  assert.equal(pkg.bin['sentinel-hook'], 'bin/cli.mjs')
  assert.equal(pkg.private, undefined)
  assert.equal(pkg.version, (await import('./home.mjs')).VERSION)
  assert.equal(pkg.version, (await import('./rules.mjs')).SENTINEL_VERSION)
})

test('merge helpers never touch a user hook that happens to share a matcher group', () => {
  const mixed = { hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'echo mine' }, { type: 'command', command: 'node "/h/.vigilia/sentinel-hook/current/scripts/sentinel/witness.mjs" --agent claude-code' }] }] } }
  assert.deepEqual(removeOurHooks(mixed), { hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'echo mine' }] }] } })
  const added = addOurHooks(mixed, 'witness', 'node "/h/.vigilia/sentinel-hook/current/scripts/sentinel/witness.mjs" --agent claude-code')
  assert.equal(added.hooks.PreToolUse[0].hooks.length, 1)
  assert.equal(ourCommands(added), 4)
})

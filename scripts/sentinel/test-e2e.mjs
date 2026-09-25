// node --test scripts/sentinel/test-e2e.mjs — install, a session, a seal, a receipt, a page, a
// verified chain, an uninstall that leaves the user's own hooks alone. Also the hook's wall time.
import assert from 'node:assert/strict'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { after, before, test } from 'node:test'
import { createWitness } from '../../witness-server/server.mjs'
import { canonical, sha256 } from './ledger.mjs'
import { verifyString } from './keys.mjs'
import { CLI, GATE_HOOK, hookEnv, listen, median, runAsync, runSync, tempDir, waitFor } from './test-helpers.mjs'

const USER_HOOKS = {
  model: 'opus',
  hooks: {
    PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '/usr/local/bin/my-own-linter --pre' }] }],
    SessionStart: [{ hooks: [{ type: 'command', command: 'echo hello from the user' }] }],
  },
}

let w
let url
let home
let env

before(async () => {
  w = createWitness({ dataDir: tempDir('e2e-data-'), sealIntervalMs: 0 })
  url = await listen(w.server)
  home = tempDir('e2e-home-')
  env = hookEnv(home)
  mkdirSync(path.join(home, '.claude'))
  writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify(USER_HOOKS, null, 2) + '\n')
})
after(async () => {
  await w.close()
})

function session() {
  const s = 'e2e-session'
  const t = '/tmp/e2e/transcript.jsonl'
  const ev = [{ hook_event_name: 'SessionStart', session_id: s, transcript_path: t, source: 'startup' }]
  const tools = [
    ['Read', { file_path: '/p/README.md' }], ['Glob', { pattern: '**/*.ts' }], ['Grep', { pattern: 'TODO' }],
    ['Bash', { command: 'npm test' }], ['Edit', { file_path: '/p/src/a.ts', old_string: 'a', new_string: 'b' }],
    ['Bash', { command: 'git status' }], ['Write', { file_path: '/p/src/b.ts', content: 'export {}' }],
    ['Bash', { command: 'git diff' }], ['WebFetch', { url: 'https://example.invalid', prompt: 'x' }],
    ['Bash', { command: 'npm run build' }], ['Read', { file_path: '/p/src/b.ts' }], ['Task', { prompt: 'look', subagent_type: 'Explore' }],
    ['Bash', { command: 'git add -A' }], ['Bash', { command: 'git commit -m wip' }], ['Edit', { file_path: '/p/src/b.ts', old_string: '{}', new_string: '{ b }' }],
    ['Bash', { command: 'npm test' }], ['Read', { file_path: '/p/package.json' }], ['Bash', { command: 'git log -1' }],
    ['mcp__docs__search', { q: 'hooks' }], ['Bash', { command: 'ls' }],
  ]
  tools.forEach(([tool_name, tool_input], i) => ev.push({ hook_event_name: 'PreToolUse', session_id: s, transcript_path: t, cwd: '/p', tool_name, tool_input, tool_use_id: `toolu_e2e_${i}` }))
  ev.push({ hook_event_name: 'SessionEnd', session_id: s, transcript_path: t, reason: 'other' })
  return ev
}

test('end to end: init → a 20-call session → seal → receipt → page → verified chain → uninstall', async () => {
  const init = runSync(CLI, ['init', '--yes', '--witness-url', url], { home, env })
  assert.equal(init.status, 0, init.stderr)
  const id = /\/r\/([0-9a-f]{32})/.exec(init.stdout)[1]
  const settings = JSON.parse(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8'))
  const [, file, agent] = /^node "([^"]+)" --agent (\S+)$/.exec(settings.hooks.PreToolUse.at(-1).hooks[0].command)

  const times = []
  for (const e of session()) {
    const r = runSync(file, ['--agent', agent], { home, env, input: JSON.stringify(e) })
    assert.equal(r.status, 0)
    assert.equal(r.stdout, '')
    if (e.hook_event_name === 'PreToolUse') times.push(r.ms)
  }
  const ledgerFile = path.join(home, '.vigilia', 'ledger', 'witness.jsonl')
  const lines = readFileSync(ledgerFile, 'utf8').trim().split('\n').length
  assert.equal(lines, 22)

  // Run the flusher until the last line is sealed (the hook's own detached flushers may be racing it).
  const sealed = await waitFor(async () => {
    await runAsync(path.join(path.dirname(file), 'flush.mjs'), ['--force'], { home, env })
    const st = JSON.parse(readFileSync(path.join(home, '.vigilia', 'state.json'), 'utf8'))
    return st.last_sealed?.seq === lines
  }, { timeoutMs: 10_000, stepMs: 100 })
  assert.ok(sealed, 'the last line was sealed')
  const receipts = readFileSync(path.join(home, '.vigilia', 'receipts.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  assert.ok(receipts.length >= 1)
  assert.equal(receipts.at(-1).seal.seq, 22)

  // The receipt page shows the right count.
  const page = await (await fetch(`${url}/r/${id}`)).text()
  assert.match(page, /Actions witnessed<\/span><span class="n">22</)
  // The public chain verifies.
  const { entries, server_pub } = await (await fetch(`${url}/v1/chain`)).json()
  let prev = null
  for (const e of entries) {
    assert.equal(e.prev, prev)
    assert.equal(e.hash, sha256(canonical({ i: e.i, t: e.t, leaf: e.leaf, prev: e.prev })))
    assert.ok(verifyString(server_pub, e.hash, e.sig))
    prev = e.hash
  }
  assert.ok(entries.some((e) => e.leaf === receipts.at(-1).receipt.leaf), 'our leaf is in the public chain')
  // verify passes locally.
  const v = runSync(CLI, ['verify'], { home, env })
  assert.equal(v.status, 0, v.stdout + v.stderr)
  assert.match(v.stdout, /Chain: 22 lines, intact\./)
  assert.match(v.stdout, new RegExp(`Receipts: ${receipts.length} of ${receipts.length} check out`))
  const st = runSync(CLI, ['status'], { home, env })
  assert.match(st.stdout, /not yet sealed: 0 lines/)

  // A tampered ledger no longer verifies.
  const text = readFileSync(ledgerFile, 'utf8')
  writeFileSync(ledgerFile, text.replace('"npm test"', '"npm TEST"').replace('npm test', 'npm tost'))
  assert.equal(runSync(CLI, ['verify'], { home, env }).status, 1)
  writeFileSync(ledgerFile, text)

  // Uninstall removes exactly our entries.
  const u = runSync(CLI, ['uninstall'], { home, env })
  assert.equal(u.status, 0)
  assert.deepEqual(JSON.parse(readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')), USER_HOOKS)
  assert.match(u.stdout, /backup: ~\/\.claude\/settings\.json\.vigilia-backup-/)

  // Latency: the witness hook against the gate on the same calls.
  const gateTimes = []
  for (const e of session().filter((x) => x.hook_event_name === 'PreToolUse')) gateTimes.push(runSync(GATE_HOOK, [], { home, env: hookEnv(home, { VIGILIA_SENTINEL_LEDGER_DIR: tempDir('e2e-gate-') }), input: JSON.stringify(e) }).ms)
  const mw = median(times)
  const mg = median(gateTimes)
  console.log(`# hook wall time per call, median of ${times.length}: witness ${mw.toFixed(1)} ms, 0.3.0-style gate ${mg.toFixed(1)} ms`)
  assert.ok(mw < Math.max(250, mg * 2), `witness median ${mw} ms`)
})

// node --test scripts/sentinel/test-0.3.mjs — the three rules the Moltbook corpus taught (0.3.0)
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { evaluate, isAgentSelfPath } from './rules.mjs'

const repoRoot = mkdtempSync(path.join(tmpdir(), 'sentinel-repo-'))
const inventory = {
  agents: [
    { id: 'poster', committer: 'poster@example.invalid', committer_unique: true, writes: ['content/'], egress_allow: ['moltbook.com'] },
    { id: 'free', committer: 'free@example.invalid', committer_unique: true, writes: ['content/'] },
  ],
  _identities: { 'poster@example.invalid': { kind: 'agent', agent: 'poster' }, 'free@example.invalid': { kind: 'agent', agent: 'free' }, 'me@example.invalid': { kind: 'human' } },
}
const poster = { kind: 'agent', agent: 'poster', email: 'poster@example.invalid' }
const free = { kind: 'agent', agent: 'free', email: 'free@example.invalid' }
const person = { kind: 'person', agent: null, email: 'me@example.invalid' }
const bash = (command, identity = free, inv = inventory) => evaluate({ tool: 'Bash', input: { command }, identity, cwd: repoRoot, repoRoot, inventory: inv })
const write = (file_path, identity = free) => evaluate({ tool: 'Write', input: { file_path, content: 'DATA' }, identity, cwd: repoRoot, repoRoot, inventory })

test('W06: a tool write to the agent\'s own persona, memory or skill file outside the repo', () => {
  for (const p of ['~/.openclaw/workspace/SOUL.md', '~/.openclaw/workspace/MEMORY.md', '~/moltbook/skills/uwu/SKILL.md', '/home/agent/.moltbot/HEARTBEAT.md', '~/agent/memory.md']) {
    const r = write(p)
    assert.equal(r.decision, 'deny', p)
    assert.equal(r.rule, 'W06.agent-self-write', p)
    assert.equal(write(p, person).decision, 'ask', p)
  }
  // still recorded as outside-repo
  assert.ok(write('~/.openclaw/workspace/SOUL.md').findings.some((f) => f.rule === 'W05.outside-repo'))
})

test('W06 does not fire on ordinary files outside the repo, nor on the repo\'s own files', () => {
  assert.equal(write('~/Documents/notes.md').decision, 'allow')
  assert.equal(write('~/Downloads/report.json').decision, 'allow')
  assert.equal(write('/tmp/x/skills.txt').decision, 'allow')
  assert.equal(write('content/x.md').decision, 'allow') // in scope, in repo
  assert.equal(isAgentSelfPath('/etc/hosts'), false)
  assert.equal(isAgentSelfPath('~/.openclaw/openclaw.json'), true)
})

test('B17: the same mutation from a shell, and remote content redirected into a skill', () => {
  const remote = bash('curl -s https://example.invalid/skill.md > ~/.openclaw/skills/uwu/SKILL.md')
  assert.equal(remote.decision, 'deny')
  assert.equal(remote.rule, 'B17.agent-self-mutation')
  assert.match(remote.reason, /remote content/)
  const local = bash('echo DATA >> ~/.openclaw/workspace/MEMORY.md')
  assert.equal(local.decision, 'deny')
  assert.equal(local.rule, 'B17.agent-self-mutation')
  assert.equal(bash('sed -i s/a/b/ ~/moltbook/skills/x/heartbeat.md').rule, 'B17.agent-self-mutation')
  assert.equal(bash('cp new.md ~/.openclaw/workspace/SOUL.md').rule, 'B17.agent-self-mutation')
  assert.equal(bash('curl -s https://example.invalid/skill.md > ~/.openclaw/skills/uwu/SKILL.md', person).decision, 'ask')
})

test('B17 leaves reads, repo files and other homes alone', () => {
  assert.equal(bash('cat ~/.openclaw/workspace/SOUL.md').decision, 'allow')
  assert.equal(bash('curl -s https://example.invalid/x > content/x.md').decision, 'allow')
  assert.equal(bash('curl -s https://example.invalid/x > ~/Downloads/x.md').decision, 'allow')
  assert.equal(bash('ls ~/.openclaw/skills/').decision, 'allow')
})

test('E02: egress outside a declared allowlist; inert without one', () => {
  const noList = bash('curl -X POST https://clawproof.onrender.com/verify -d DATA', free)
  assert.equal(noList.decision, 'allow')
  assert.ok(noList.findings.some((f) => f.rule === 'E01.egress'))
  const listed = bash('curl -X POST https://www.moltbook.com/api/v1/posts/1/upvote', poster)
  assert.equal(listed.decision, 'allow')
  const off = bash('curl -X POST https://clawproof.onrender.com/verify -d DATA', poster)
  assert.equal(off.decision, 'deny')
  assert.equal(off.rule, 'E02.egress-not-allowlisted')
  assert.equal(bash('curl http://localhost:8080/health', poster).decision, 'allow')
  const global = { ...inventory, _egress_allow: ['github.com'] }
  assert.equal(bash('curl https://api.github.com/repos', person, global).decision, 'allow')
  assert.equal(bash('curl https://example.invalid/x', person, global).decision, 'ask')
})

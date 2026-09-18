/**
 * rules.mjs — the sentinel's rules. Deterministic, no model anywhere in the blocking path.
 *
 * A tool call comes in as { tool, input, identity, cwd, repoRoot, inventory } and goes out as
 * { decision, rule, reason, severity, findings }. `decision` is one of allow | ask | deny.
 * `findings` are observations that do not change the decision but belong on the record
 * (an egress host, a reserved path written by a person, a call from an unattributed agent).
 *
 * Two identity profiles decide how hard a rule bites:
 *   agent   — a declared agent (from VIGILIA_AGENT or the git committer email the inventory
 *             calls an agent). Out-of-scope writes, reserved paths, credentials, destructive
 *             and remote-code commands are all DENIED.
 *   person  — a human or a live session. Catastrophic commands are DENIED; the rest is ASKED,
 *             because a person may legitimately edit the inventory or read a .env file.
 *   unconfigured — a container that never set its git identity. Treated as a person for scope
 *             (there is no scope to enforce) but the call is recorded as unattributed, which is
 *             the agent ledger's own finding made visible at the moment it happens.
 *
 * The rule ids are stable; the paper and the ledger refer to them by id.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const SENTINEL_VERSION = '0.1.1'

/** Paths no agent may write, whatever the inventory says. Mirrors scripts/check-agent-scope.mjs. */
export const RESERVED_PATHS = [
  '_config/agents.json',
  '_config/routines/',
  '.github/',
  'scripts/check-agent-scope.mjs',
  'scripts/sentinel/',
  '.claude/settings.json',
]

/** Files whose contents are credentials. Matched against a path relative to $HOME or the repo. */
export const CREDENTIAL_PATH_RX = [
  /(^|\/)\.aws\/(credentials|config)$/,
  /(^|\/)\.ssh\/(id_[a-z0-9]+|[^/]+\.pem|authorized_keys|config)$/,
  /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/,
  /(^|\/)\.netrc$/,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.pypirc$/,
  /(^|\/)\.docker\/config\.json$/,
  /(^|\/)\.config\/gh\/hosts\.yml$/,
  /(^|\/)\.kube\/config$/,
  /(^|\/)\.git-credentials$/,
  /(^|\/)Library\/Keychains\//,
  /^\/etc\/(shadow|sudoers)$/,
  /(^|\/)\.config\/op\//,
  /(^|\/)\.1password\//,
  /\.(p12|pfx|keystore)$/,
]
const CREDENTIAL_EXEMPT_RX = [/\.env\.(example|sample|template|dist)$/]

/** Files an agent could write to survive its own session. AgentWorm's persistence vector. */
export const PERSISTENCE_PATH_RX = [
  /(^|\/)\.(zshrc|zprofile|bashrc|bash_profile|profile|zshenv)$/,
  /(^|\/)\.gitconfig$/,
  /(^|\/)\.claude\/(settings|settings\.local)\.json$/,
  /(^|\/)\.claude\/CLAUDE\.md$/,
  /(^|\/)\.ssh\/authorized_keys$/,
  /(^|\/)Library\/LaunchAgents\//,
  /(^|\/)Library\/LaunchDaemons\//,
  /^\/etc\//,
  /(^|\/)\.config\/systemd\//,
  /(^|\/)crontab$/,
]

// ---------------------------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------------------------

/** `writes` entries: a directory ("dir/", everything under it), a glob (one star spans one path segment), or an exact file. */
export function matchesWrite(pattern, file) {
  if (pattern.endsWith('/')) return file.startsWith(pattern)
  if (!pattern.includes('*')) return file === pattern
  const rx = new RegExp(
    '^' +
      pattern
        .split('**')
        .map((part) =>
          part
            .split('*')
            .map((lit) => lit.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
            .join('[^/]*'),
        )
        .join('.*') +
      '$',
  )
  return rx.test(file)
}

export function isReserved(rel) {
  return RESERVED_PATHS.some((p) => (p.endsWith('/') ? rel.startsWith(p) : rel === p))
}

function anyRx(list, s) {
  return list.some((rx) => rx.test(s))
}

export function isCredentialPath(p) {
  const s = expandHome(p)
  if (anyRx(CREDENTIAL_EXEMPT_RX, s)) return false
  return anyRx(CREDENTIAL_PATH_RX, s)
}

export function isPersistencePath(p) {
  return anyRx(PERSISTENCE_PATH_RX, expandHome(p))
}

function expandHome(p) {
  const home = process.env.HOME || ''
  if (p === '~') return home
  if (p.startsWith('~/')) return path.join(home, p.slice(2))
  return p.replace(/^\$\{?HOME\}?(?=\/|$)/, home)
}

/** Resolve a tool path against cwd; return { abs, rel, inRepo }. rel is repo-relative when inRepo. */
export function locate(p, cwd, repoRoot) {
  const abs = path.resolve(cwd, expandHome(p))
  if (!repoRoot) return { abs, rel: null, inRepo: false }
  const rel = path.relative(repoRoot, abs)
  const inRepo = rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel)
  return { abs, rel: inRepo ? rel.split(path.sep).join('/') : null, inRepo }
}

// ---------------------------------------------------------------------------------------------
// Bash normalisation — so that `\rm -r -f "$HOME"`, `'rm' -fr ~` and `sh -c "rm -rf ~"` all read
// as the same thing. Everything here is string transformation; nothing is executed.
// ---------------------------------------------------------------------------------------------

function decodeBase64Tokens(s) {
  const out = []
  for (const m of s.matchAll(/(^|\s)([A-Za-z0-9+/]{8,}={0,2})(?=\s|$)/g)) {
    try {
      const dec = Buffer.from(m[2], 'base64').toString('utf8')
      // Keep only decodings that look like a command: printable, with a space or a slash in them.
      if (dec && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(dec) && /[ /]/.test(dec)) out.push(dec)
    } catch {
      /* not base64 */
    }
  }
  return out
}

function decodeHexEscapes(s) {
  return s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
}

export function normalizeCommand(cmd) {
  let s = String(cmd)
  s = s.replace(/\\\r?\n/g, ' ') // line continuations
  s = decodeHexEscapes(s)
  s = s.replace(/\\(?=[A-Za-z])/g, '') // \rm -> rm
  s = s.replace(/[\u00a0\u2000-\u200b\u202f\u3000]/g, ' ') // exotic spaces
  s = s.replace(/["'`]/g, '') // dequote: exposes sh -c "..." and 'rm' to the same patterns
  s = s.replace(/\$\(\s*(printf|echo)\s+([^)]*)\)/g, '$2') // $(printf rm) -> rm
  s = s.replace(/\s+/g, ' ').trim()
  const decoded = decodeBase64Tokens(s)
  return decoded.length ? s + ' ' + decoded.join(' ') : s
}

// ---------------------------------------------------------------------------------------------
// Bash rules
// ---------------------------------------------------------------------------------------------

const ROOT_LIKE = new Set(['/', '/*', '~', '~/', '~/*', '$HOME', '${HOME}', '$HOME/', '$HOME/*', '${HOME}/', '..', '../', '../*', '.', './', '*', ':/'])

function operandsAfter(cmdWordRx, s) {
  // Everything after the first occurrence of the command word, minus flags.
  const m = s.match(cmdWordRx)
  if (!m) return null
  const rest = s.slice(m.index + m[0].length)
  const stop = rest.search(/[|;&]/)
  const seg = stop === -1 ? rest : rest.slice(0, stop)
  return seg
    .split(' ')
    .map((t) => t.replace(/[)\]}]+$/, '')) // `system(rm -rf ~)` leaves `~)`; the operand is `~`
    .filter((t) => t && !t.startsWith('-') && t !== 'rm')
}

function classifyOperand(op, cwd, repoRoot) {
  if (ROOT_LIKE.has(op)) return 'catastrophic'
  if (/^(\/Users\/[^/]+|\/home\/[^/]+|\/root)\/?$/.test(expandHome(op))) return 'catastrophic'
  if (/^\/(etc|usr|bin|sbin|var|opt|lib|boot|System|Library|Applications|Volumes|dev|mnt\/[a-z])(\/|$)/.test(op)) return 'catastrophic'
  if (/^[A-Za-z]:\\/.test(op)) return 'catastrophic'
  if (/^(\/tmp|\/private\/tmp|\/var\/folders|\/var\/tmp|\$TMPDIR|\$\{TMPDIR\})\/./.test(op)) return 'inside' // scratch space is the agent's own
  if (op.startsWith('$') || op.startsWith('%')) return 'variable'
  const { inRepo } = locate(op, cwd, repoRoot)
  if (path.isAbsolute(expandHome(op)) || op.startsWith('~') || op.startsWith('..')) {
    return inRepo ? 'inside' : 'outside'
  }
  return 'inside'
}

const BASH_RULES = [
  // Each rule: id, test(s, ctx) -> false | { reason, severity, agent, person }
  {
    id: 'B01.rm-recursive-catastrophic',
    test(s, ctx) {
      if (!/(^|[\s;&|(])(sudo )?rm /.test(s)) return false
      const ops = operandsAfter(/(^|[\s;&|(])(sudo )?rm /, s) || []
      const cls = ops.map((o) => classifyOperand(o, ctx.cwd, ctx.repoRoot))
      if (cls.includes('catastrophic')) return { reason: 'rm on a root, home or system path', severity: 'critical', agent: 'deny', person: 'deny' }
      if (cls.includes('outside')) return { reason: 'rm on a path outside the repository', severity: 'high', agent: 'deny', person: 'ask' }
      if (cls.includes('variable') && /-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|--recursive|--force/.test(s)) return { reason: 'recursive forced rm on an unresolved variable', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B02.recursive-force-on-protected-operand',
    // Any command word at all: `$X -rf ~`, `xargs rm -rf`, `foo -fr $HOME`.
    test(s) {
      if (!/(^|\s)(-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*|-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*|--recursive|--force)(\s|$)/.test(s)) return false
      const toks = s.split(' ')
      if (toks.some((t) => ROOT_LIKE.has(t))) return { reason: 'recursive/force flags with a root-like operand', severity: 'critical', agent: 'deny', person: 'deny' }
      return false
    },
  },
  {
    id: 'B03.find-delete-catastrophic',
    test(s, ctx) {
      if (!/(^|[\s;&|(])find .*(-delete|-exec (sudo )?rm)/.test(s)) return false
      const ops = operandsAfter(/(^|[\s;&|(])find /, s) || []
      const first = ops[0]
      if (!first) return false
      // `find .` is the working tree, which is the agent's own workspace; only root, home, system
      // and outside-repository start points are catastrophic here.
      const cls = first === '.' || first === './' ? 'inside' : classifyOperand(first, ctx.cwd, ctx.repoRoot)
      if (cls === 'catastrophic') return { reason: 'find -delete from a root, home or system path', severity: 'critical', agent: 'deny', person: 'deny' }
      if (cls === 'outside') return { reason: 'find -delete outside the repository', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B04.disk-or-filesystem-wipe',
    test(s) {
      if (/(^|[\s;&|(])(mkfs(\.|\s)|wipefs|shred|diskutil (erase|reformat|zeroDisk|randomDisk)|dd .*of=\/dev\/|> ?\/dev\/(sd|disk|nvme|hd))/.test(s)) return { reason: 'disk or filesystem wipe', severity: 'critical', agent: 'deny', person: 'deny' }
      return false
    },
  },
  {
    id: 'B05.fork-bomb',
    test(s) {
      if (/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(s)) return { reason: 'fork bomb', severity: 'critical', agent: 'deny', person: 'deny' }
      return false
    },
  },
  {
    id: 'B06.chmod-chown-recursive-root',
    test(s) {
      if (/(^|[\s;&|(])(sudo )?(chmod|chown) (-R|--recursive) \S+ (\/|~|\$HOME)(\s|$)/.test(s)) return { reason: 'recursive permission change on root or home', severity: 'critical', agent: 'deny', person: 'deny' }
      return false
    },
  },
  {
    id: 'B07.git-history-or-remote-destruction',
    test(s) {
      if (/(^|[\s;&|(])git push\b(?!.*--force-with-lease).*(--force|\s-f\b|--delete|\s:\S)/.test(s)) return { reason: 'force push or remote branch deletion', severity: 'high', agent: 'deny', person: 'ask' }
      if (/(^|[\s;&|(])git (reset --hard|clean -[a-zA-Z]*f[a-zA-Z]*|branch -D|checkout -- \.|restore \.|restore :\/|stash (drop|clear))/.test(s)) return { reason: 'discards uncommitted or committed work', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B08.database-destruction',
    test(s) {
      if (/\b(drop (table|database|schema)|truncate( table)? \w|delete from \w+ ?;)/i.test(s)) return { reason: 'destructive SQL', severity: 'high', agent: 'deny', person: 'ask' }
      if (/(^|[\s;&|(])(supabase db reset|prisma migrate reset|rails db:(drop|reset)|dropdb\b|supabase projects delete)/.test(s)) return { reason: 'database reset or drop', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B09.infrastructure-destruction',
    test(s) {
      const rx = [
        /(^|[\s;&|(])fly(ctl)? (apps?|machines?|volumes?|postgres|secrets) (destroy|delete|rm|unset)\b/,
        /(^|[\s;&|(])vercel (rm|remove|projects? rm|env rm)\b/,
        /(^|[\s;&|(])gh (repo delete|release delete|secret delete)\b/,
        /(^|[\s;&|(])aws (s3 rm .*--recursive|s3 rb\b|s3api delete-bucket|ec2 terminate-instances|rds delete-db-instance|iam delete-|lambda delete-function|dynamodb delete-table|cloudformation delete-stack)/,
        /(^|[\s;&|(])terraform (destroy|apply -destroy)\b/,
        /(^|[\s;&|(])kubectl delete (ns|namespace|pv|pvc|deployment|statefulset|node|--all)\b/,
        /(^|[\s;&|(])docker (system prune -a|volume (rm|prune)|rm -f|container prune)\b/,
        /(^|[\s;&|(])railway (volume delete|service delete|down|delete)\b/,
        /\b(volumeDelete|serviceDelete|projectDelete|deleteBackup|environmentDelete)\b/, // GraphQL mutations (PocketOS)
        /(^|[\s;&|(])npm unpublish\b/,
        /(^|[\s;&|(])(gcloud (compute instances delete|sql instances delete|projects delete)|az (group delete|vm delete))\b/,
        /(^|[\s;&|(])crontab -r\b/,
      ]
      if (rx.some((r) => r.test(s))) return { reason: 'destroys infrastructure, data or a deployment', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B10.remote-code-execution',
    test(s) {
      if (/(^|[\s;&|(])(curl|wget) [^|]*\| ?(sudo )?(sh|bash|zsh|python3?|node|perl|ruby)\b/.test(s)) return { reason: 'downloads and executes code in one step', severity: 'high', agent: 'deny', person: 'ask' }
      if (/(^|[\s;&|(])(sh|bash|zsh) <\( ?(curl|wget)/.test(s)) return { reason: 'downloads and executes code in one step', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B11.decode-and-execute',
    test(s) {
      if (/base64 (-d|--decode|-D)\b.*\| ?(sudo )?(sh|bash|zsh|eval|source|python3?|node)\b/.test(s)) return { reason: 'decodes and executes hidden content', severity: 'critical', agent: 'deny', person: 'deny' }
      if (/(^|[\s;&|(])eval [$(]/.test(s)) return { reason: 'eval of computed content', severity: 'medium', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B12.interpreter-file-destruction',
    test(s) {
      if (/(^|[\s;&|(])(python3?|node|perl|ruby) (-c|-e) .*(rmtree|rmSync|rmdirSync|unlinkSync|os\.remove|os\.unlink|os\.rmdir|shutil\.|fs\.rm|FileUtils\.rm|File\.delete|unlink\()/.test(s)) return { reason: 'file deletion through an inline interpreter', severity: 'high', agent: 'deny', person: 'ask' }
      // An inline interpreter that shells out: the inner command is judged by the other rules once
      // dequoted, but a `system(` / `subprocess` / `child_process` call with rm in it is its own class.
      if (/(^|[\s;&|(])(python3?|node|perl|ruby) (-c|-e) .*(system\(|subprocess\.|child_process|execSync|os\.system|popen\().*(^|[\s(])rm /.test(s)) return { reason: 'shells out to rm from an inline interpreter', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B13.credential-exfiltration',
    test(s) {
      const cred = /(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|id_ecdsa|\.aws\/credentials|\.netrc|hosts\.yml|\.npmrc|\.pypirc|\.kube\/config|\.git-credentials|\.docker\/config\.json)/
      if (/(^|[\s;&|(])(curl|wget|nc|ncat|scp|rsync|ftp|sftp)\b/.test(s) && cred.test(s) && /(-d|--data|--data-binary|-F|--form|-T|--upload-file|@|\s\S+@\S+:)/.test(s)) {
        return { reason: 'sends a credential file over the network', severity: 'critical', agent: 'deny', person: 'deny' }
      }
      if (/(^|[\s;&|(])(printenv|env|set)\b[^|]*\| ?(curl|wget|nc)\b/.test(s)) return { reason: 'pipes the environment to the network', severity: 'critical', agent: 'deny', person: 'deny' }
      return false
    },
  },
  {
    id: 'B14.credential-read',
    test(s) {
      const cred = /(^|\s|=)(~|\$HOME|\/Users\/[^/ ]+|\/home\/[^/ ]+|\/root)?\/?[^ ]*(\.aws\/credentials|\.ssh\/id_[a-z0-9]+|\.ssh\/[^ ]+\.pem|\.env(\.[A-Za-z0-9_.-]+)?|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|\.config\/gh\/hosts\.yml|\.kube\/config|\.git-credentials|\/etc\/shadow)(\s|$)/
      if (/\.env\.(example|sample|template|dist)\b/.test(s)) return false
      if (cred.test(s)) return { reason: 'reads a credential file', severity: 'high', agent: 'deny', person: 'ask' }
      if (/(^|[\s;&|(])security (find-generic-password|find-internet-password|dump-keychain)\b/.test(s)) return { reason: 'reads the macOS keychain', severity: 'high', agent: 'deny', person: 'ask' }
      if (/(^|[\s;&|(])op (read|item get)\b/.test(s)) return { reason: 'reads a 1Password item', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
  {
    id: 'B15.reserved-path-mutation',
    test(s, ctx) {
      if (ctx.identity.kind !== 'agent') return false
      const mentionsReserved = RESERVED_PATHS.some((p) => s.includes(p.replace(/\/$/, '')))
      if (!mentionsReserved) return false
      if (/(>|>>|(^|[\s;&|(])(tee|sed -i|cp|mv|rm|truncate|git (checkout|restore) --|chmod|chown|ln -s?f?)\b)/.test(s)) return { reason: 'mutates a reserved path from a shell command', severity: 'high', agent: 'deny', person: 'allow' }
      return false
    },
  },
  {
    id: 'B16.persistence-mutation',
    test(s) {
      if (/(^|[\s;&|(])crontab( -e\b| [^-\s])/.test(s)) return { reason: 'installs a scheduled job', severity: 'high', agent: 'deny', person: 'ask' }
      const persist = /(\.(zshrc|zprofile|bashrc|bash_profile|profile|zshenv)|\.gitconfig|\.claude\/settings(\.local)?\.json|authorized_keys|LaunchAgents|LaunchDaemons|\/etc\/(hosts|profile|sudoers|cron))/
      if (!persist.test(s)) return false
      if (/(>|>>|(^|[\s;&|(])(tee|sed -i|cp|mv|ln|launchctl (load|bootstrap)|defaults write)\b)/.test(s)) return { reason: 'writes to a persistence location', severity: 'high', agent: 'deny', person: 'ask' }
      return false
    },
  },
]

function egressHosts(s) {
  const hosts = new Set()
  for (const m of s.matchAll(/https?:\/\/([^/\s"'<>]+)/g)) hosts.add(m[1].toLowerCase())
  for (const m of s.matchAll(/(^|[\s;&|(])(ssh|scp|sftp|rsync) [^|;&]*?([A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:|\s|$)/g)) hosts.add(m[4].toLowerCase())
  return [...hosts]
}

// ---------------------------------------------------------------------------------------------
// The evaluator
// ---------------------------------------------------------------------------------------------

const ORDER = { allow: 0, ask: 1, deny: 2 }

/**
 * @param {object} ctx
 * @param {string} ctx.tool            Bash | Write | Edit | MultiEdit | NotebookEdit | Read | ...
 * @param {object} ctx.input           the tool's input
 * @param {object} ctx.identity        { kind: 'agent'|'person'|'unconfigured', agent?: string, email?: string }
 * @param {string} ctx.cwd
 * @param {string|null} ctx.repoRoot
 * @param {object|null} ctx.inventory  parsed _config/agents.json, or null
 */
export function evaluate(ctx) {
  const profile = ctx.identity.kind === 'agent' ? 'agent' : 'person'
  const findings = []
  let best = { decision: 'allow', rule: null, reason: 'no rule matched', severity: null }
  const raise = (id, r) => {
    const decision = r[profile] || 'allow'
    if (ORDER[decision] > ORDER[best.decision]) best = { decision, rule: id, reason: r.reason, severity: r.severity }
    else if (decision !== 'allow') findings.push({ rule: id, note: r.reason })
  }
  if (ctx.identity.kind === 'unconfigured') findings.push({ rule: 'I01.unattributed', note: 'no agent identity configured; scope cannot be enforced' })

  if (ctx.tool === 'Bash') {
    const raw = String(ctx.input?.command ?? '')
    const s = normalizeCommand(raw)
    for (const rule of BASH_RULES) {
      const r = rule.test(s, ctx)
      if (r) raise(rule.id, r)
    }
    const hosts = egressHosts(s)
    if (hosts.length) findings.push({ rule: 'E01.egress', note: hosts.join(',') })
    return { ...best, findings }
  }

  const p = ctx.input?.file_path ?? ctx.input?.notebook_path ?? ctx.input?.path ?? null
  if (!p) return { ...best, findings }
  const loc = locate(p, ctx.cwd, ctx.repoRoot)
  const isWrite = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(ctx.tool)
  const isRead = ctx.tool === 'Read'

  if (isCredentialPath(loc.abs) || (loc.rel && isCredentialPath(loc.rel))) {
    if (isWrite) raise('W03.credential-file-write', { reason: 'writes a credential file', severity: 'high', agent: 'deny', person: 'ask' })
    if (isRead) raise('R01.credential-file-read', { reason: 'reads a credential file', severity: 'high', agent: 'deny', person: 'allow' })
    if (isRead && profile === 'person') findings.push({ rule: 'R01.credential-file-read', note: 'credential file read by a person' })
  }
  if (isWrite && !loc.inRepo && isPersistencePath(loc.abs)) {
    raise('W04.persistence-write', { reason: 'writes a persistence location outside the repository', severity: 'high', agent: 'deny', person: 'ask' })
  }
  if (isWrite && loc.inRepo) {
    if (isReserved(loc.rel)) {
      raise('W01.reserved-path', { reason: 'writes a path reserved from every agent', severity: 'high', agent: 'deny', person: 'allow' })
      if (profile === 'person') findings.push({ rule: 'W01.reserved-path', note: 'reserved path written by a person' })
    } else if (ctx.identity.kind === 'agent') {
      const rec = ctx.inventory?.agents?.find((a) => a.id === ctx.identity.agent)
      const writes = rec?.writes ?? []
      if (!writes.some((w) => matchesWrite(w, loc.rel))) {
        raise('W02.out-of-scope', { reason: `not in ${ctx.identity.agent}'s declared writes`, severity: 'high', agent: 'deny', person: 'allow' })
      }
    }
  }
  if (isWrite && !loc.inRepo) findings.push({ rule: 'W05.outside-repo', note: 'write outside the repository' })
  return { ...best, findings }
}

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

export function classifyIdentity({ envAgent, email, inventory }) {
  const agents = inventory?.agents ?? []
  if (envAgent && agents.some((a) => a.id === envAgent)) return { kind: 'agent', agent: envAgent, email: email || null, via: 'env' }
  const e = (email || '').toLowerCase()
  if (!e) return { kind: 'person', agent: null, email: null, via: 'none' }
  const who = inventory?._identities?.[e]
  if (who?.kind === 'agent' && who.agent) return { kind: 'agent', agent: who.agent, email: e, via: 'identity' }
  const byCommitter = agents.find((a) => a.committer_unique === true && [a.committer].flat().map((x) => String(x).toLowerCase()).includes(e))
  if (byCommitter) return { kind: 'agent', agent: byCommitter.id, email: e, via: 'committer' }
  if (who?.kind === 'unconfigured') return { kind: 'unconfigured', agent: null, email: e, via: 'identity' }
  if (who?.kind === 'human' || who?.kind === 'session') return { kind: 'person', agent: null, email: e, via: 'identity' }
  return { kind: 'person', agent: null, email: e, via: 'unknown-email' }
}

/** sha256 of this rules file, so every record says which ruleset judged it. */
export function rulesDigest() {
  try {
    return createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex')
  } catch {
    return null
  }
}

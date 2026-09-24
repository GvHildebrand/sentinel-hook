# How the sentinel works

The short version is in the paper (`paper/vigilia-sentinel-2026.pdf`, sections 4 and 5). This is the
operator's version.

## Where it runs

Claude Code lets a project register hooks in `.claude/settings.json`. The sentinel registers three:
`SessionStart` and `SubagentStart` (a heartbeat: the control was present, with this ruleset) and
`PreToolUse` on `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and `Read` (a decision before
the tool runs). Project hooks run in every session in the repository, scheduled cloud sessions
included, and in every subagent a session spawns. An enterprise policy can pin them so user settings
cannot switch them off.

## Identity first

Before deciding what a call may do, the sentinel decides who is making it:

- `VIGILIA_AGENT=<id>` in the environment names a declared agent.
- Otherwise the git committer email (`git config user.email`) is looked up in `_config/agents.json`
  (`_identities`, and each agent's `committer` where `committer_unique` is true).
- A known human or session email, or no email at all, is a **person**.
- An email the inventory marks `unconfigured` (a container that never set its identity) gets no
  scope enforced and every call recorded as unattributed (rule `I01`).

Without an inventory file, everyone is a person: the destructive-command rules still apply.

## The rules

27 identifiers (24 in 0.2.0; B17, W06 and E02 came from the Moltbook corpus in 0.3.0). Two profiles decide how hard each bites: for an **agent**, everything below denies;
for a **person**, the catastrophic classes deny and the rest ask.

| Id | What it catches |
|---|---|
| B01 | `rm` on a root, home or system path (deny for everyone); on a path outside the repository (agent deny, person ask); recursive force on an unresolved variable |
| B02 | recursive/force flags with a root-like operand, whatever the command word (`$X -rf ~`, `xargs rm -rf`) |
| B03 | `find -delete` / `-exec rm` from root, home, a system path or outside the repository |
| B04 | disk and filesystem wipes (`mkfs`, `dd of=/dev/…`, `diskutil erase…`, `shred`, `wipefs`) |
| B05 | fork bomb |
| B06 | recursive `chmod`/`chown` on root or home |
| B07 | force push, remote branch deletion, `reset --hard`, `clean -f`, `branch -D`, discarding the working tree |
| B08 | `DROP`, `TRUNCATE`, unfiltered `DELETE`, database resets |
| B09 | infrastructure destruction: Fly, Vercel, GitHub, AWS, Terraform, Kubernetes, Docker, Railway (including the GraphQL mutations), crontab removal |
| B10 | download-and-execute in one step (`curl … \| sh`, `bash <(curl …)`) |
| B11 | decode-and-execute (`base64 -d … \| sh`), `eval` of computed content |
| B12 | file deletion or a shell-out to `rm` from an inline interpreter (`python3 -c`, `node -e`, `perl -e`) |
| B13 | credential exfiltration: uploading a credential file, piping the environment to the network |
| B14 | credential reads (`~/.ssh/id_*`, `~/.aws/credentials`, `.env*` except examples, keychain, 1Password CLI) |
| B15 | an agent mutating a reserved path from a shell command |
| B16 | writes to persistence locations (shell profiles, `authorized_keys`, LaunchAgents, the agent's own settings, crontab) |
| B17 | a shell write (redirect, `tee`, `sed -i`, `cp`/`mv` destination) into the agent's own persona, memory, heartbeat, skill or runtime-config file outside the repository; a stronger reason when the content comes from `curl`/`wget` (a skill installed by redirect) |
| W01 | a write to a reserved path (the inventory, the standing orders, `.github/`, the sentinel itself) |
| W02 | a write outside the agent's declared `writes` |
| W03 | a write to a credential file |
| W04 | a write to a persistence location outside the repository |
| W05 | recorded only: a write outside the repository |
| W06 | a tool write to the agent's own persona, memory, heartbeat, skill or runtime-config file outside the repository (`~/.openclaw/…`, `~/.claude/…`, any `SOUL.md`, `MEMORY.md`, `HEARTBEAT.md`, `SKILL.md` or `skills/<name>/…` under a home directory) |
| R01 | a read of a credential file |
| I01 | recorded only: an unattributed identity |
| E01 | recorded only: every network host named in a command |
| E02 | egress to a host outside a declared allowlist (`_egress_allow` in the inventory for everyone, `egress_allow` on an agent; a suffix covers its subdomains; loopback always allowed). Inert when no list is declared |

Before matching, a shell command is normalised: line continuations, `\xHH` escapes and backslash
prefixes are resolved, quotes are removed (so `sh -c "…"` is read as the command it carries),
`$(printf …)` is expanded, and, when the command contains a decoder (`base64 -d`, `xxd -r`), any
token that decodes to a printable string containing a space or a slash is appended to the text
under examination. Nothing is executed.

**Text a command carries is data (0.2.0).** Before normalisation, on the raw text where quotes and
line breaks still mean something, the body of a heredoc and the argument of a leading `echo` or
`printf` are replaced by `DATA` unless that text reaches something that executes it: the heredoc
feeds a shell or interpreter, the segment pipes into a bare shell or interpreter, `eval`, `source`,
`xargs` or a decoder, or the file it writes is run later in the same command. `echo 'rm -rf ~'`
prints a string; `echo 'rm -rf ~' | sh` runs it; `echo 'rm -rf ~' > c.sh; sh c.sh` runs it too.
The first day of live use produced two denials on commands that only quoted the string, and the
first stranger test met the same class twice; that is why.

Three other 0.2.0 corrections from the first day of live use: B16 matches persistence paths only
when anchored to the home directory or the system (the project's own `.claude/settings.json` is a
reserved path, B15/W01, not a persistence location); B10 fires only when the download's sink
executes what it reads (a bare shell, or an interpreter with no inline program and no script file:
`curl … | node -e "…"` is a data pipeline); B15's mutating verb must be a statement's command word
and, for `cp`/`mv`, the reserved path must be the destination.

## What the Moltbook corpus taught (0.3.0)

On 2026-09-24 the 0.2.0 rules were run over the actions solicited by the 9,249 posts the Moltbook
Observatory Archive's own label calls prompt injection (Vigilia, *What a host-side gate can see*,
github.com/GvHildebrand/moltbook-watch). The gate could see 91 % of those posts and stopped 0.5 %, and
three of its misses were the gate's own, not the category's:

- **478 payloads asked the reading agent to rewrite its own memory, heartbeat or persona file** under
  `~/.openclaw/`. 0.2.0 recorded each as a write outside the repository (W05) and allowed it, because a
  repository was the only write scope it knew. A memory file is where an injection becomes a habit. → **W06**
  for tool writes, **B17** for the same mutation from a shell.
- **1,508 payloads redirected remote content into a skills directory** (`curl -s <url> > ~/moltbook/skills/<name>/…`).
  B10 did not fire because nothing executes in the same command. → **B17**'s remote-content reason.
- **3,833 calls went to one third-party host** and thousands more to others. A host-side gate cannot know a host is
  hostile; an operator can say which hosts an agent has any business reaching. → **E02**, inert until an
  allowlist is declared.

What the corpus also showed, and no host-side rule can fix: 14,406 solicited actions were authenticated calls
to the platform's own API (upvote, follow, subscribe), the agent spending its credentials on someone else's
behalf. That is a trust-boundary decision for the platform, and the README says so.

The three rules were written from the January–April posts and scored on the April–September posts the
authors had never opened; both numbers are in the paper.

## The ledger

One JSONL file per identity under `research/sentinel/ledger/`, **at the nearest `.git` above the
session's working directory** — so a project nested inside another repository writes into the outer
one. `VIGILIA_SENTINEL_LEDGER_DIR` overrides the location; with no `.git` anywhere above, the
fallback is `~/.vigilia-sentinel/`. The file is named after the identity: `<agent-id>.jsonl` for a
declared agent, `person-<git-email-slug>.jsonl` for a person, `unconfigured-….jsonl` for a
container that never set its identity.

Each line: timestamp, event,
identity and how it was resolved, subagent id if any, tool, a redacted excerpt of the target and a
sha256 of the full command, decision, rule, severity, reason, findings, sentinel version, sha256 of
the rules file, `prev` (previous line's hash) and `hash` (sha256 of the canonical line). `verify()`
in `ledger.mjs` walks the chain and reports the first broken line.

## The seal

`templates/sentinel-attest.yml` runs on every push that changes a ledger and once a day. It
verifies every chain, writes a manifest of the chain heads, signs it keylessly with cosign (the
signature and the workflow's OIDC identity are entered in the Sigstore Rekor transparency log),
requests an RFC 3161 timestamp for the same manifest from DigiCert's public authority, and commits
the attestation, bundle and timestamp reply under its own identity. Verification is in
`docs/verify.md`.

**Sessions without a heartbeat (0.2.0).** The manifest also lists every commit in the sealed range
made by a declared agent that runs Claude Code (`runner: cloud-routine`) and whether that agent's
ledger holds a heartbeat in the twelve hours before the commit. A `missing` is named in the sealing
commit. Because a routine sets its git identity a few calls into its run, its SessionStart
heartbeat lands under the unconfigured identity; since 0.2.0 the hook writes a second heartbeat
the moment an identity first resolves in a session, so the cross-check finds one under the agent's
own name. The check needs history: the workflow checks out 200 commits, not one.

**What the seal does not prove.** That the rules were right, that the ledger was not edited in the
window between a hook write and the next push, or that no unhooked session ran alongside. The
paper's §5.6 lists what the operator can still do and what trace each move leaves.

## Failure mode

The hook fails open: an internal error is written to the ledger as an `error` record and the call
proceeds. The error line is not an absence.

## What it does not do

- It sees only sessions that run hooks. A scheduled script that is not Claude Code has no sentinel.
- It has no memory across calls. Two innocent calls that add up to one destructive act pass; both
  are on the record.
- It judges shell writes (`>`, `sed -i`, `tee`) by B15 and B16 only, not by the full scope list.
- It can be uninstalled. The next session then has no heartbeat, which the sealed record shows.

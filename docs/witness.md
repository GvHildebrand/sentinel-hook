# The witness

A witness is an independent party that writes down, at the moment it is told, that a record with a
given fingerprint existed. sentinel-hook keeps the record on your machine and sends the witness only
the fingerprint. A log you hold yourself rests on your word; a log whose head was witnessed
continuously cannot be rewritten or backfilled afterwards without the gap showing.

This page covers witness mode (the default since 0.4.0). The gate is in [how-it-works.md](how-it-works.md);
what leaves the machine, in plain language, is in [privacy.md](privacy.md).

## On every call

Claude Code runs the hook on `SessionStart`, `SubagentStart`, `PreToolUse` (every tool, matcher `*`)
and `SessionEnd`. The hook (`scripts/sentinel/witness.mjs`):

1. appends one line to `~/.vigilia/ledger/witness.jsonl`;
2. if the last flush attempt was more than a minute ago, or the session is ending, starts the
   flusher as a detached process and does not wait for it;
3. exits 0 and prints nothing.

It does not decide. It prints no `deny`, no `ask`, and no `allow` either: an explicit allow from a
hook would override the agent's own permission prompt, which a witness has no business doing. Claude
Code's documentation is explicit that a hook which exits 0 with no output leaves the call to the
normal permission flow ("staying silent doesn't approve it"). The witness entry point does not import
`rules.mjs`, and `test-witness.mjs` walks its import graph to keep it so. There is no network on this
path; the median wall time per call in the end-to-end test is about 30 ms on the machine it was built on, against
about 55 ms for the gate.

The hook runs synchronously (not `async: true`), so the line is written before the tool runs.

## The line

```json
{"v":1,"ts":"…","nonce":"<16 random bytes, hex>","event":"PreToolUse","agent":"claude-code",
 "session":"…","mode":"witness","version":"0.4.0","tool":"Bash","tool_use_id":"toolu_…",
 "transcript_path":"…","input_sha256":"…","target":"<redacted excerpt>","seq":42,"prev":"…","hash":"…"}
```

- `hash` is the sha256 of the canonical JSON of the line without `hash`; `prev` is the previous
  line's `hash`. Editing or deleting any line breaks every hash after it.
- `seq` is the line's position in the chain. A gap or a repeat fails `verify`.
- `tool_use_id` and `transcript_path` bind the line to the agent's own transcript entry, and
  `input_sha256` (sha256 of the canonical JSON of the full `tool_input`) lets you show later that the
  tool call in the transcript is the one recorded, without the ledger holding it.
- `target` is a bounded, redacted excerpt of the command or path, for you to read. It never leaves
  the machine.
- `nonce` is what makes the line's hash unguessable. A sha256 of `git push --force` could be found by
  hashing likely commands; a hash of a line carrying 128 random bits cannot. That is why the line hash,
  and nothing derived from a command, is what gets sealed.

Parallel sessions and subagents write to the same file. Appends take a lock file (created with
O_EXCL, a short jittered wait, a lock older than five seconds treated as stale). If the lock cannot be
had within about a second the line is written anyway with `"lock": false`: a possibly visible fork is
better than a lost entry or a stalled agent.

## The key

On first run (`init`, or the first flush) the hook generates an ed25519 key pair with `node:crypto`.
The private key is written to `~/.vigilia/keys/ed25519.pem` (mode 0600, directory 0700) and never
leaves the machine; the witness never generates or holds it. The **install id** is the first 32 hex
characters of the sha256 of the raw public key. It names your receipt page and nothing else.

Losing the key means a new install id: the witness sees a new key whose count starts where your
ledger is. Old receipts stay verifiable, since each carries the seal it answers.

## The seal

The flusher (`scripts/sentinel/flush.mjs`) sends only the latest head. Because every line commits to
the one before it, sealing the head seals everything before it.

```json
{ "v": 1, "pub": "<raw ed25519 public key, base64url>", "head": "<hash of the latest line>",
  "seq": 42, "ts": "<client ISO time>", "sig": "<ed25519 over the canonical JSON of the other five>" }
```

`POST /v1/seal`, content-type and `user-agent: sentinel-hook/<version>` only, five-second timeout,
no redirects followed. The witness answers with a signed receipt, which the flusher checks and appends
to `~/.vigilia/receipts.jsonl`:

```json
{ "i": 1234, "t": "2026-09-24T12:00:00Z", "leaf": "<sha256 of the canonical seal>", "prev": "…",
  "hash": "<sha256 of canonical {i,t,leaf,prev}>", "server_sig": "…", "server_pub": "…" }
```

## The witness's own chain

The server (`witness-server/`) keeps two files:

- `seals.jsonl` — **private**. The full seal messages, so it can count per install and rebuild its
  state after a restart.
- `chain.jsonl` — **public**. Per entry only `{ i, t, leaf, prev, hash, sig }`. `leaf` is the sha256 of
  the canonical seal, including your signature; nobody can link a leaf to an install without the seal,
  and only you and the witness hold that. `sig` is the witness's ed25519 signature over `hash`.

`GET /v1/head` returns the latest entry and the witness's public key; `GET /v1/chain?from=&to=` pages
through the chain (at most 1,000 entries per request). A scheduled job
([templates/witness-mirror.yml](../templates/witness-mirror.yml)) copies the head to a Git repository
every six hours after checking the signature, the pinned key and that the last mirrored entry has not
changed, then signs it into Sigstore Rekor and gets an RFC 3161 timestamp for it. The witness cannot
rewrite its own history without that mirror disagreeing.

A seal whose `seq` is lower than the last one from the same key is accepted, recorded and flagged
`regress`; the same `seq` with a different head is flagged `rewrite`. It is not silently refused:
the record that a count went backwards is the evidence a witness exists to produce. The receipt page
says so when it happened. A reinstall that deletes the ledger but keeps the key produces exactly this.

## Checking it yourself

`npx @vigilia/sentinel-hook verify` walks your chain, then for every stored receipt checks that the
leaf is the hash of the seal you sent, that the entry hash recomputes, that the witness signed it,
that the seal is signed by your key, and that the sealed head is line `seq` of your chain.

To show a third party that a line existed no later than a seal time, give them the ledger up to that
line and the matching line of `receipts.jsonl` (your seal and the witness's receipt). They recompute the chain, `leaf = sha256(canonical(seal))` and
`hash = sha256(canonical({i,t,leaf,prev}))`, check `server_sig` against the witness key, and look the
entry up at `/v1/chain?from=<i>&to=<i+1>` or in the mirror. `canonical` is sorted keys, no whitespace
(`scripts/sentinel/ledger.mjs`).

## What a seal proves, and what it does not

It proves that a record whose head had this hash, and this many lines, existed no later than the time
the witness received the seal, and that those lines were not changed afterwards: any later edit breaks
the chain against the sealed head.

It does not prove:

- what an action did, or that the agent's tool call did what its input says;
- that the ledger captured every action. If the hook was removed, disabled or bypassed, nothing was
  recorded; what the witness shows is that seals stopped, and when;
- anything about tools the hook does not see (anything outside Claude Code's hooks, a shell you type
  into yourself, another agent);
- that the lines were true when written. The hook writes them, not the agent, but whoever controls
  the machine controls the hook;
- anything between two seals until the next one arrives. The flusher seals at most once a minute and
  on session end; a record rewritten before its first seal leaves no trace at the witness.

## Near-misses (opt-in)

In gate mode, with `npx @vigilia/sentinel-hook near-miss --auto on`, each deny or ask sends
`{ v, pub, category, entry?, ts, sig }`: one of `destructive_command`, `credential_exposure`,
`unreviewed_push`, `injection_suspected`, `other`, and the hash of the ledger line it refers to. No
free text. `near-miss <category> [--entry <hash>]` sends one by hand. Witness mode never decides, so
it never produces one on its own. The mapping from rule ids is in `categoryForRule()`
(`scripts/sentinel/witness-client.mjs`).

## The receipt page and the weekly feed

`https://witness.aivigilia.com/r/<install id>` shows, to anyone holding the address: actions
witnessed (the latest `seq`), seals, first seen (date), last sealed (to the minute, UTC), near-misses
by category if any were reported, what every install reported over the last seven days (aggregate
categories only), and how to verify. It is `noindex` and sends no referrer. The id is derived from
your public key, which the witness does not publish, so the address is not guessable; it is not
secret once you share it.

`/r/<install id>/feed.xml` is an Atom feed with one entry per ISO week, including weeks with no seal.
Subscribing is the opt-in weekly digest; there is no email anywhere.

## When things go wrong

| What | What happens |
|---|---|
| The witness is down or unreachable | Nothing blocks. The flusher records the failure in `~/.vigilia/state.json` and backs off (one minute, doubling, at most six hours). The next seal covers everything before it. `status` shows the last error. |
| The witness says "too soon" (429) | Not a failure: the next attempt is after `retry-after`. |
| Your clock is more than ten minutes off | The witness refuses the seal (`ts` out of range); `status` shows it. Fix the clock. |
| The hook itself errors | An `error` line is written and the call proceeds. |
| `node` is not on the PATH Claude Code gives its hooks (a GUI launch with Node from a version manager) | The hook cannot start; Claude Code reports a hook error and the call proceeds. Nothing is recorded, and `status` shows the line count not moving. |
| Two writers at once | The lock serialises them; if it cannot, the line says `lock: false`. |
| `VIGILIA_WITNESS=off`, `--offline`, or `witness: false` in `~/.vigilia/config.json` | Local ledger only. Nothing is sent, including near-misses. |
| Uninstall | Hooks removed; the ledger, key and receipts stay. The receipt page keeps its last seal time. |

## Files

```
~/.vigilia/config.json            mode, witness URL, opt-ins, settings files touched (0600)
~/.vigilia/keys/ed25519.pem       your private key (0600, never sent)
~/.vigilia/ledger/witness.jsonl   your record
~/.vigilia/receipts.jsonl         the witness's signed receipts
~/.vigilia/state.json             last flush, backoff, last sealed head
~/.vigilia/sentinel-hook/<ver>/   the runtime the hooks point at; `current` is a symlink
```

`VIGILIA_SENTINEL_LEDGER_DIR` moves the ledger (set it for the CLI too, or `status` and `verify` will
look in the default place).

## Other coding agents

0.4.0 hooks Claude Code only. Cursor and Codex are detected by `init` and named in one line; nothing
is written into their configuration. What their documentation says, read on 2026-09-24:

- **Cursor** — [cursor.com/docs/agent/hooks](https://cursor.com/docs/agent/hooks). Hooks live in
  `~/.cursor/hooks.json` (and per project). `postToolUse`, `sessionStart` and `sessionEnd` are
  documented as observational (their output does not gate anything), and pre-action hooks that exit 0
  with no output let the action proceed. So a witness that never decides is possible there. It is
  not shipped because the input fields differ from Claude Code's (`conversation_id`, not
  `session_id`), `postToolUse` fires after the action rather than before it, the documentation also
  says invalid output on a permission hook blocks the action, and none of it has been run against a
  live Cursor. A malformed hooks file in a stranger's editor is a harm the witness must not cause.
- **Codex CLI** — [learn.chatgpt.com/docs/hooks](https://learn.chatgpt.com/docs/hooks) (redirected
  from developers.openai.com/codex/hooks). `~/.codex/hooks.json` with `SessionStart`, `PreToolUse`,
  `PostToolUse` and `SessionEnd`, input fields close to Claude Code's, and "exits 0 with no output"
  treated as success. But Codex requires the user to review and trust each non-managed hook
  definition (`/hooks`) before it runs; an installer cannot and should not grant that. Not yet run
  against a live Codex either.

Both are the next candidates, each with its own adapter and a test against the real agent.

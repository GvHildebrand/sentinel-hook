# sentinel-hook

**A free Swiss witness for your coding agent.**

It seals a fingerprint of every action your agent takes, as it happens. If something goes wrong, you can show exactly what your agent did, and anyone can check that the record hasn't been touched since.

It works with Claude Code, observes and never decides; an opt-in gate can allow, ask or deny instead. The record stays on your machine; only its fingerprint goes to the witness in Geneva.

<!-- PRE-LAUNCH. Written as it will read at launch. Not live yet:
  - the npm package @vigilia/sentinel-hook is not published (from a clone: node bin/cli.mjs <command>);
  - the witness at https://witness.aivigilia.com is not deployed (seals fail open and wait; to try it,
    run witness-server/ locally and pass --witness-url http://127.0.0.1:8787);
  - the privacy page https://aivigilia.com/witness/privacy is not up (the draft is docs/privacy.md);
  - the repository has not moved to github.com/aivigilia/sentinel-hook yet (it is GvHildebrand/sentinel-hook).
-->

## Quickstart

```bash
npx @vigilia/sentinel-hook init
```

That witnesses every Claude Code session on this machine: it adds its hooks to `~/.claude/settings.json` (backed up first; your other hooks are left alone) and keeps the record in `~/.vigilia/ledger/witness.jsonl`. Needs Node 20 or later. Nothing to configure.

**What leaves your machine:** your code, commands and prompts never leave it. Only a fingerprint, a count, the time and a signature do. Never file paths or repository names either. [docs/privacy.md](docs/privacy.md)

```bash
npx @vigilia/sentinel-hook status      # mode, lines recorded, chain verified, last seal
npx @vigilia/sentinel-hook verify      # check your chain and the witness's signed receipts
npx @vigilia/sentinel-hook receipt     # your receipt page: https://witness.aivigilia.com/r/<id>
npx @vigilia/sentinel-hook uninstall   # removes only its own hooks; your record and key stay
```

`init` options: `--project` (this repository only, `./.claude/settings.json`), `--offline` (local record, nothing sent), `--dry-run` (show, change nothing), `--yes` (no question).

## The gate (opt-in)

```bash
npx @vigilia/sentinel-hook init --gate
```

Adds a deterministic allow/ask/deny before every Bash, Write, Edit and Read call, against 27 rules for destructive commands, credential access and out-of-scope writes. **The gate can block real work:** a denied call does not run, and the rules are sometimes wrong. That is why it is not the default. Running `init` without `--gate` returns to the witness. Rules and the repository-checkout setup: [docs/how-it-works.md](docs/how-it-works.md).

## How it works

- The witness: what is recorded, what a seal proves and what it does not, failure modes — [docs/witness.md](docs/witness.md).
- The gate and its rules — [docs/how-it-works.md](docs/how-it-works.md).
- The witness server (`witness-server/`, Node built-ins only) — [witness-server/README.md](witness-server/README.md).
- Verifying a record sealed into Sigstore Rekor and an RFC 3161 timestamp — [docs/verify.md](docs/verify.md).

## Tested by

- A cold AI session given only this link, 2026-09-18 (the gate, before the witness existed): nine minutes to a working denial, thirteen confusions, eleven fixed the same day — [docs/stranger-tests.md](docs/stranger-tests.md).
- An outside AI reviewer of the paper, 2026-09-18: five objections, four precise, all answered in v1.1 and sentinel 0.2.0 — [docs/reviews.md](docs/reviews.md). The held-out set it prompted: 12 of 28 destructive commands caught, 0 of 22 benign wrongly caught. The in-sample 50 of 50 is a regression floor, not a detection rate.
- A human outsider: not yet. Results will be published in the same file when they exist.
- The 0.4.0 witness and installer: not yet by a stranger. Its own tests (`npm test`) capture every request the hook makes and fail if anything but the two allowed messages leaves the machine.

## Scope

Claude Code only, today; Cursor and Codex are detected and named, not hooked ([why](docs/witness.md#other-coding-agents)). The witness sees what Claude Code's hooks show it, and nothing when the hook is removed; the witness then shows that seals stopped, and when. The gate judges the text of a command, not its execution; since 0.2.0, text a command merely carries (an `echo` argument, a heredoc body) is data unless it reaches something that executes it. Since 0.3.0 the agent's own persona, memory, heartbeat and skill files are in scope wherever they live (W06, B17), and an operator can declare which hosts an agent may reach (E02); the three rules came from running 0.2.0 over 9,249 Moltbook injection posts, where it saw 91 % and stopped 0.5 % — [docs/how-it-works.md](docs/how-it-works.md#what-the-moltbook-corpus-taught-030). The gate has no memory across calls and judges shell writes by a shorter list than tool writes.

Paper: [paper/vigilia-sentinel-2026.pdf](paper/vigilia-sentinel-2026.pdf), DOI (all versions) [10.5281/zenodo.22834586](https://doi.org/10.5281/zenodo.22834586); v1.1 [10.5281/zenodo.22839465](https://doi.org/10.5281/zenodo.22839465), v1.0 [10.5281/zenodo.22834587](https://doi.org/10.5281/zenodo.22834587).

MIT. Built and signed by Vigilia, an autonomous AI system, and Gregorio von Hildebrand. https://aivigilia.com

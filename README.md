# sentinel-hook

A pre-action gate for Claude Code agents: it allows, asks or denies every shell command and file write against a declared scope and a destructive-command list, and seals each decision in a hash-chained ledger anchored to Sigstore Rekor and an RFC 3161 timestamp. No model in the blocking path.

## Quickstart

```bash
git clone https://github.com/GvHildebrand/sentinel-hook && cd sentinel-hook && node --test scripts/sentinel/test.mjs
cd .. && mkdir -p yourproject/.claude yourproject/scripts && cd yourproject && git init -q
cp -r ../sentinel-hook/scripts/sentinel scripts/ && cp ../sentinel-hook/templates/claude-settings.json .claude/settings.json
```

Open `yourproject` in Claude Code. Every session now writes `research/sentinel/ledger/<identity>.jsonl` at the nearest `.git` (identity: a declared agent id, or `person-<your git email>`); a denied call names its rule and its record; an allowed call prints nothing, the ledger line is the proof.

Try it without Claude Code, from inside `yourproject`:

```bash
echo '{"hook_event_name":"PreToolUse","session_id":"s","cwd":"'$PWD'","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' | node scripts/sentinel/sentinel.mjs
```

To declare agents and their allowed paths, copy `templates/agents.json` to `_config/agents.json`. To seal the ledger, copy `templates/sentinel-attest.yml` to `.github/workflows/` (needs `id-token: write`).

## Verify a sealed record

Each attestation in `research/sentinel/attestations/` names its own two commands: `cosign verify-blob` against the Sigstore bundle, `openssl ts -verify` against the timestamp reply. Tools, chains and what each step proves: [docs/verify.md](docs/verify.md).

## Tested by

- A cold AI session given only this link, 2026-09-18: nine minutes to a working denial, thirteen confusions, eleven fixed the same day — [docs/stranger-tests.md](docs/stranger-tests.md).
- An outside AI reviewer of the paper, 2026-09-18: five objections, four precise, all answered in v1.1 and sentinel 0.2.0 — [docs/reviews.md](docs/reviews.md). The held-out set it prompted: 12 of 28 destructive commands caught, 0 of 22 benign wrongly caught. The in-sample 50 of 50 is a regression floor, not a detection rate.
- A human outsider: not yet. Results will be published in the same file when they exist.

## Scope

Claude Code hooks only, today. It judges the text of a command, not its execution: a command that merely quotes a dangerous string, in an `echo` or a heredoc, is denied too. It has no memory across calls, judges shell writes by a shorter list than tool writes, and can be uninstalled; the missing heartbeat is then on the record. Paper: [paper/vigilia-sentinel-2026.pdf](paper/vigilia-sentinel-2026.pdf), DOI (all versions) [10.5281/zenodo.22834586](https://doi.org/10.5281/zenodo.22834586); v1.1 [10.5281/zenodo.22839465](https://doi.org/10.5281/zenodo.22839465), v1.0 [10.5281/zenodo.22834587](https://doi.org/10.5281/zenodo.22834587). How it works: [docs/how-it-works.md](docs/how-it-works.md).

MIT. Built and signed by Vigilia, an autonomous AI system, and Gregorio von Hildebrand. https://aivigilia.com

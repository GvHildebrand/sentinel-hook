# sentinel-hook

A pre-action gate for Claude Code agents: it allows, asks or denies every shell command and file write against a declared scope and a destructive-command list, and seals each decision in a hash-chained ledger anchored to Sigstore Rekor and an RFC 3161 timestamp. No model in the blocking path.

## Quickstart

```bash
git clone https://github.com/GvHildebrand/sentinel-hook && cd sentinel-hook
node --test scripts/sentinel/test.mjs          # 17 tests
mkdir -p yourproject/.claude yourproject/scripts
cp -r scripts/sentinel yourproject/scripts/ && cp templates/claude-settings.json yourproject/.claude/settings.json
```

Open `yourproject` in Claude Code. Every session now writes `research/sentinel/ledger/<identity>.jsonl`; a denied call says which rule and which record.
To declare agents and their allowed paths, copy `templates/agents.json` to `_config/agents.json`. To seal the ledger, copy `templates/sentinel-attest.yml` to `.github/workflows/` (needs `id-token: write`).

## Verify a sealed record

Each attestation in `research/sentinel/attestations/` names its own two commands: `cosign verify-blob` against the Sigstore bundle, `openssl ts -verify` against the timestamp reply. See [docs/verify.md](docs/verify.md).

## Tested by

- A cold AI session given only this link: [docs/stranger-tests.md](docs/stranger-tests.md), every confusion recorded.
- A human outsider: not yet. Results will be published in the same file when they exist.

## Scope

Claude Code hooks only, today. It has no memory across calls, judges shell writes by a shorter list than tool writes, and can be uninstalled; the missing heartbeat is then on the record. Paper: [paper/vigilia-sentinel-2026.pdf](paper/vigilia-sentinel-2026.pdf). How it works: [docs/how-it-works.md](docs/how-it-works.md).

MIT. Built and signed by Vigilia, an autonomous AI system, and Gregorio von Hildebrand. https://aivigilia.com

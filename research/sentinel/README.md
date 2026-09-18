# research/sentinel — the sentinel's record

What is here is written by scripts, not by the agents they watch. Code: `scripts/sentinel/`.

- `ledger/<identity>.jsonl` — one hash-chained file per identity (a declared agent, a person, an
  unconfigured container). Every line is a heartbeat (the sentinel was present in a session), a
  decision (allow, ask or deny, with the rule and a bounded, redacted excerpt of the target), or an
  error. `prev` is the previous line's hash; `hash` is the sha256 of the canonical line. Verify a
  file with `node -e` against `scripts/sentinel/ledger.mjs` `verify()`, or trust the attestation.
- `attestations/<utc>-<commit>.json` — written by the `sentinel attest` workflow: a manifest of
  every ledger's chain head, the Rekor log index and integrated time from the Sigstore bundle
  next to it, and the RFC 3161 timestamp from an independent authority in the `.tsr`. The
  `verify` block inside each file holds the two commands that check it.
- `eval/` — results of `replay.mjs` (the rules run over this repository's whole git history) and
  `eval-corpus.mjs` (the rules run over the incident-derived corpus and its variants).

What the sentinel does not see: agents that do not run Claude Code (`source-fetcher`,
`observer-daily`), file writes made through shell redirection rather than the Write and Edit
tools (the post-push scope gate covers those), and anything an operator does after uninstalling
it — except that the missing heartbeat is then on the record.

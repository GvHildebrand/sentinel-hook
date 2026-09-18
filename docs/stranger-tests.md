# Stranger tests

The README is not done until someone who did not write it has used it. Each test below was run by
a stranger given only the repository link, with no help. Confusions are recorded as found, in the
tester's own words; what was fixed afterwards is marked in the status list under it, not edited out.

## Test 1 — a cold AI session, 2026-09-18

Run by a Claude session in a fresh directory with no prior knowledge of the project, capped at 25
tool calls. Its report, unedited:

> - **Time from first read of the README to a working denial:** 9 minutes, 6 tool calls (11 calls and 12 minutes for the full test including verify.md and writing the file).
>
> - **What worked first time:**
>   - `git clone` + `node --test scripts/sentinel/test.mjs` — 17/17 pass on Node 24, exactly as promised.
>   - The `mkdir -p` / `cp -r` lines — nothing missing, nothing renamed.
>   - Piping a Claude Code `PreToolUse` JSON with `rm -rf ~` to `node scripts/sentinel/sentinel.mjs` returned a well-formed `permissionDecision: "deny"` naming rule `B01.rm-recursive-catastrophic` and the record id. `ls -la` was allowed silently and recorded. `SessionStart` produced a heartbeat.
>   - verify.md step 3 on my ledger: `ok: true, lines: 4, brokenAt: null`.
>   - The shipped attestation checks out without cosign: sha256 of the first 6 lines matches the manifest, and the attested head is still a line in the now-50-line ledger.
>
> - **Confusions, in the order met:**
>   1. README says only "Open `yourproject` in Claude Code" — nothing on how to exercise the hook by hand; I had to already know the hook JSON protocol.
>   2. `templates/claude-settings.json`'s comment cites `scripts/check-agent-scope.mjs`, which is not in the repository.
>   3. README: "Every session now writes `research/sentinel/ledger/<identity>.jsonl`" — it wrote into the **clone's** root, not `yourproject/`, because the hook walks up to the nearest `.git` and the Quickstart nests `yourproject` inside the clone. A literal reader gets a dirty clone and no ledger in their project.
>   4. `<identity>` is undefined in the README; it came from my global `git config user.email` (`person-gregorio-vonhildebrand-gmail-com.jsonl`, `via: unknown-email`).
>   5. `CLAUDE_PROJECT_DIR` does not move the ledger; only the undocumented `VIGILIA_SENTINEL_LEDGER_DIR` does, and with no git root it silently falls back to `~/.vigilia-sentinel`.
>   6. `echo 'rm -rf ~'` is denied identically to `rm -rf ~` — the gate judges text, not execution. The same software running on the host blocked my own session **twice**: once for echoing the string into a pipe, once for a heredoc that merely quoted it in this report. The README's "judges shell writes by a shorter list" does not warn about this.
>   7. A benign call prints nothing (exit 0, empty stdout); only the ledger shows it was recorded.
>   8. verify.md step 3 run from inside `yourproject` returns `{ ok: true, lines: 0, head: null }` for a ledger that **does not exist** — a missing ledger verifies as intact.
>   9. verify.md's certificate identity is `^https://github.com/GvHildebrand/vigilia/`, not this repo; the shipped seal was made by a different repository the README never names.
>   10. The attestation's embedded command says `manifest.json` (file is `<stamp>.manifest.json`) and `-CAfile <tsa-chain.pem>`, a literal placeholder.
>   11. verify.md step 2 needs `digicert-tsa-chain.pem` — not in the repo, no URL.
>   12. README names `cosign verify-blob` but never says to install cosign or where from; it was absent here, so step 1 cannot run from the README alone.
>   13. README: "A cold AI session given only this link: docs/stranger-tests.md, every confusion recorded" — the file says "_Pending_".
>
> - **Promised but could not verify:** the Rekor and RFC 3161 anchoring (no cosign, no CA chain — only the chain hashes and manifest sha256 could be checked); whether Claude Code actually surfaces the deny text to the user; the `sentinel-attest.yml` workflow and `_config/agents.json` scoping (not exercised); the stranger-test file itself.
>
> - **Would I install it?** Yes in a repo where I already accept a deny-by-text gate, but three things would stop me installing it blind: it denies commands for *containing* a dangerous string rather than executing one (it blocked writing this very report), the ledger lands at the nearest `.git` rather than in the project the README names, and `verify()` says `ok: true` on a nonexistent ledger — so the one check a stranger can run without cosign cannot tell "sealed and intact" from "never wrote anything".

### Status after the test (v0.1.1, same day)

| # | Status |
|---|---|
| 1 | Fixed: the README now shows how to drive the hook by hand. |
| 2 | Fixed: the template's comment no longer cites a file outside this repository. |
| 3 | Fixed: the quickstart creates the project beside the clone, not inside it. |
| 4, 5 | Fixed in docs: `docs/how-it-works.md` names the ledger file, the `VIGILIA_SENTINEL_LEDGER_DIR` override and the nearest-`.git` rule. |
| 6 | **Open, by design for now.** The gate judges the text of a command, and a string that would be catastrophic if executed is treated as catastrophic when it is merely echoed or quoted. That is a false positive a person meets by asking a documentation tool to write about destructive commands; it is also what makes `sh -c "…"`, `echo … \| sh` and the base64 forms catchable. The README now says so. A rule that treats `echo`/heredoc content as data unless it reaches a shell or a persistence path is the candidate fix and needs its own corpus entries before it ships. |
| 7 | Fixed in docs: an allowed call prints nothing; the ledger line is the proof. |
| 8 | Fixed in code: `verify()` returns `ok: false, why: "missing"` for a file that does not exist; a test covers it. |
| 9 | Fixed in docs: the seals in this repository were produced by Vigilia's fleet repository (`GvHildebrand/vigilia`), which is why the identity names it; your own workflow seals under your repository's identity, and the attestation now records `sealed_by`. |
| 10 | Fixed in code: the embedded commands name `<stamp>.manifest.json` and point to `docs/verify.md` for the chain. |
| 11, 12 | Fixed in docs: `docs/verify.md` links the cosign installer and DigiCert's root-certificate page. |
| 13 | Fixed: this file. |

## Test 2 — a human outsider

Not yet run. When it is, the tester's own words go here, unedited, with the date and how long the
quickstart took.

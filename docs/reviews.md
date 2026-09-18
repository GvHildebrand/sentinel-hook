# Reviews

Outside reviews of the paper and the sentinel, recorded verbatim, with what changed and what did
not. A review that changes nothing is recorded too, with the reason.

## Review 1 — an AI reviewer, 2026-09-18, on paper v1.0

Gregorio von Hildebrand asked a separate AI system to check the published paper. Its assessment,
unedited:

> Is it relevant? Yes, and the timing is good. Agent incidents are frequent and public, the EU AI Act requires logging and incident reporting, and auditors and insurers will want evidence that oversight actually ran. "Operator-independent proof that oversight ran" is a real need.
>
> Where a serious reviewer would push back
>
> 1. The central claim is overstated. The seal proves the record wasn't backdated. It doesn't prove the record is complete or truthful. The operator controls the hook, the rules and the machine, can edit the ledger before it's sealed, and can run sessions without the hook. The heartbeat only reveals a gap if someone knows a session happened. Section 7 admits most of this, but the abstract's "third-party-verifiable evidence that oversight existed and fired" reads stronger than what's delivered.
> 2. The evaluation is in-sample. The rules were written from the same incidents the test set was built from, so 50/50 is expected. 40 hand-picked benign commands say little about false alarms in real use. 0 of 200 injection payloads changing a decision is true by construction, since a pattern matcher has nothing to persuade. There's one fleet, one day of live use, and no outside tester yet.
> 3. The incident data is biased. The finding that the harmed person almost always noticed first is partly built in. Incidents caught quietly by automated monitors rarely make the press, so a press-based sample will over-represent victim-detected cases. With 16 cases and order-of-magnitude detection times, it's suggestive, not a finding.
> 4. The "empty quadrant" claim is risky. Faramesh, Microsoft's Agent Governance Toolkit and Brömme are close neighbours. Anchoring a log that already exists to a public transparency log will look like a small step to some reviewers.
> 5. An AI drafted it, with no peer review and no institutional backing. Readers will check the references harder than usual. Many are recent, from 2026, and I can't confirm they all exist, so it's worth a manual pass over each one. One wrong citation would hurt credibility badly.

### What we checked before answering

- The sentinel's own ledger for the day the paper was written: 285 decisions under the 0.1 rules,
  13 of them non-allow, all 13 false positives on review. Point 2 was not hypothetical.
- Every one of the 52 references, fetched: two citation titles wrong, seven never cited in the
  body, three unreachable by tool, two behind bot walls, the rest resolving with matching titles.
- Whether a scheduled cloud session had actually run under the hook: one had, at 19:17 UTC, and
  its heartbeat had landed under an unattributed identity.

### Verdict and changes (paper v1.1, sentinel 0.2.0)

| # | Verdict | What changed |
|---|---|---|
| 1 | Precise | Abstract and §5.4 now claim "a record … that a third party can verify was not produced after the fact"; new §5.6 lists what the operator can still do and the write-to-seal window; new §5.7 makes the heartbeat check mechanical: the attester lists every commit by a hooked agent in the sealed range and whether its ledger holds a heartbeat |
| 2 | Precise | Corpus labelled in-sample; a held-out set built after the rules were frozen (commit `e5bcc78`, rules hash recorded at evaluation) from three sources not consulted when writing them: **12 of 28 caught, 0 of 22 false positives**; new §6.4 reports the first day of live use and its 13 false positives; the three classes are fixed in 0.2.0 and the 14 commands are regression items; 0/200 kept but labelled a consistency check |
| 3 | Precise | Selection-bias paragraph in §2; "in the public record" and "pattern" replace "finding"; Anthropic's 1-in-47,000 blocked actions cited as evidence that quiet catches exist |
| 4 | Partly | §8 already positioned against all three and said "we add nothing to their engines"; Figure 2 now plots Faramesh, Microsoft AGT, Brömme and agent-provenance, and §3 says "no deployed, evaluated system we found, as of 18 September 2026" |
| 5 | Precise | Five uncited references removed; two titles corrected; the CFAA cited as 18 U.S.C. § 1030; SWIM given its DOI; the Codex incident cited to the primary post; every web source dated |

### Not adopted

- Rewriting the contribution as "a small step": the paper already says so in those words, and
  now says why the step is the smallest that moves the record out of the claimant's hands.
- Removing the 0/200 payload result: relabelled, not removed.
- Changing the incident table: the bias is stated; the table stands.
- Any model in the blocking path.

# Sentinel — replay over git history

Generated 2026-09-18T16:27:19.259Z at `96a48bb` by `scripts/sentinel/replay.mjs`: 364 non-merge commits, every file of every agent-attributed commit evaluated against today's inventory (W01 reserved paths, W02 declared scope).

| Agent | Commits | Files | Attributed by | Before declaration: commits / files / would-deny | After declaration: commits / files / would-deny |
|---|---|---|---|---|---|
| `agent-ledger` | 9 | 28 | identity 8, prefix 1 | 0 / 0 / **0** | 9 / 28 / **0** |
| `journalism-thread-check` | 25 | 34 | identity 25 | 0 / 0 / **0** | 25 / 34 / **0** |
| `warnings-daily` | 34 | 276 | identity 26, prefix 8 | 7 / 188 / **32** | 27 / 88 / **0** |
| `source-fetcher` | 32 | 103 | identity 32 | 0 / 0 / **0** | 32 / 103 / **0** |
| `gtm-taskforce` | 37 | 160 | prefix 37 | 4 / 4 / **0** | 33 / 156 / **15** |
| people and live sessions | 218 | 2141 | — | reserved-path writes: 26 | (allowed; recorded) |
| unconfigured containers | 9 | 48 | — | files outside every declared scope: 30 | (unattributable) |

### `warnings-daily` — would have been denied, before declaration (32)

| Commit | Date | File | Rule | Attributed by |
|---|---|---|---|---|
| 1fae1b9 | 2026-09-05 | `src/app/[locale]/warnings/[slug]/page.tsx` | W02.out-of-scope | prefix |
| 1fae1b9 | 2026-09-05 | `src/app/[locale]/warnings/page.tsx` | W02.out-of-scope | prefix |
| 1fae1b9 | 2026-09-05 | `src/components/editorial/timeline.tsx` | W02.out-of-scope | prefix |
| 1fae1b9 | 2026-09-05 | `src/lib/warnings.ts` | W02.out-of-scope | prefix |
| e87eea2 | 2026-09-05 | `src/app/[locale]/warnings/[slug]/page.tsx` | W02.out-of-scope | prefix |
| e87eea2 | 2026-09-05 | `src/app/[locale]/warnings/page.tsx` | W02.out-of-scope | prefix |
| e87eea2 | 2026-09-05 | `src/app/warnings.json/route.ts` | W02.out-of-scope | prefix |
| e87eea2 | 2026-09-05 | `src/lib/warnings.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `CLAUDE.md` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/de/meta.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/de/nav.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/en/meta.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/en/nav.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/es/meta.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/es/nav.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/fr/meta.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/fr/nav.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/it/meta.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `messages/it/nav.json` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/app/[locale]/warnings/[slug]/page.tsx` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/app/[locale]/warnings/page.tsx` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/app/llms.txt/route.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/app/sitemap.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/app/warnings.json/route.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/components/editorial/colophon.tsx` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/components/editorial/index.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/components/editorial/masthead.tsx` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/components/editorial/timeline.tsx` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/i18n/namespaces.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/lib/i18n/dates.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/lib/warnings.ts` | W02.out-of-scope | prefix |
| eaa5381 | 2026-09-05 | `src/middleware.ts` | W02.out-of-scope | prefix |

### `gtm-taskforce` — would have been denied, after declaration (15)

| Commit | Date | File | Rule | Attributed by |
|---|---|---|---|---|
| 55a0ed1 | 2026-09-07 | `content/TRANSLATION-BRIEF.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `content/roadmap/de/roadmap.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `content/roadmap/es/roadmap.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `content/roadmap/fr/roadmap.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `content/roadmap/it/roadmap.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `content/roadmap/roadmap.md` | W02.out-of-scope | prefix |
| 55a0ed1 | 2026-09-07 | `src/lib/pricing/ladder.ts` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `.github/workflows/citations.yml` | W01.reserved-path | prefix |
| ba5f838 | 2026-09-07 | `content/TRANSLATION-BRIEF.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `content/roadmap/de/roadmap.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `content/roadmap/es/roadmap.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `content/roadmap/fr/roadmap.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `content/roadmap/it/roadmap.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `content/roadmap/roadmap.md` | W02.out-of-scope | prefix |
| ba5f838 | 2026-09-07 | `scripts/check-citations.mjs` | W02.out-of-scope | prefix |

### Unconfigured containers — files outside every declared scope (30)

| Commit | Date | File |
|---|---|---|
| 34ca3ee | 2026-09-09 | `memory/log.md` |
| d3a6151 | 2026-09-09 | `memory/log.md` |
| ee7f6a6 | 2026-09-09 | `messages/de/records.json` |
| ee7f6a6 | 2026-09-09 | `messages/en/records.json` |
| ee7f6a6 | 2026-09-09 | `messages/es/records.json` |
| ee7f6a6 | 2026-09-09 | `messages/fr/records.json` |
| ee7f6a6 | 2026-09-09 | `messages/it/records.json` |
| ee7f6a6 | 2026-09-09 | `src/app/[locale]/records/[slug]/page.tsx` |
| ee7f6a6 | 2026-09-09 | `src/app/api/records/[slug]/subscribe/route.ts` |
| ee7f6a6 | 2026-09-09 | `src/app/api/webhooks/paddle/route.ts` |
| ee7f6a6 | 2026-09-09 | `src/components/records/subscribe-form.tsx` |
| ee7f6a6 | 2026-09-09 | `src/lib/funnel/events.ts` |
| ee7f6a6 | 2026-09-09 | `src/lib/payments/paddle.ts` |
| ee7f6a6 | 2026-09-09 | `src/lib/records.ts` |
| ee7f6a6 | 2026-09-09 | `src/lib/register/subscriptions.ts` |
| ee7f6a6 | 2026-09-09 | `worker/Dockerfile` |
| ee7f6a6 | 2026-09-09 | `worker/README.md` |
| ee7f6a6 | 2026-09-09 | `worker/tests/test_prospect.py` |
| ee7f6a6 | 2026-09-09 | `worker/vigilia_worker/__main__.py` |
| ee7f6a6 | 2026-09-09 | `worker/vigilia_worker/prospect.py` |
| 5b7a898 | 2026-09-09 | `beats/product/inbox.md` |
| 5b7a898 | 2026-09-09 | `memory/log.md` |
| 39797ce | 2026-09-09 | `scripts/paddle-prices.mjs` |
| 39797ce | 2026-09-09 | `supabase/migrations/034_register.sql` |
| 72b5718 | 2026-09-09 | `memory/log.md` |
| e38c9b6 | 2026-09-09 | `.status.md` |
| e38c9b6 | 2026-09-09 | `beats/journalism/inbox.md` |
| e38c9b6 | 2026-09-09 | `beats/product/inbox.md` |
| e38c9b6 | 2026-09-09 | `memory/log.md` |
| e38c9b6 | 2026-09-09 | `memory/reports/2026-09-09-report-to-max.md` |


#!/usr/bin/env node
/**
 * flush.mjs — the detached flusher. The hook spawns it and does not wait; it seals the latest
 * chain head with the witness and keeps the receipt (witness-client.mjs does the work).
 *
 *   node flush.mjs                              seal the latest head if anything is new
 *   node flush.mjs --force                      ignore the backoff
 *   node flush.mjs --near-miss <category> [h]   send one near-miss (gate mode, opted in); queued on failure
 *
 * It prints nothing: it runs with stdio ignored, and nothing it could say has anyone to read it.
 * Everything it learns goes to ~/.vigilia/state.json.
 */

import { readConfig } from './home.mjs'
import { flush, queueNearMiss, sendNearMiss } from './witness-client.mjs'

async function main() {
  const args = process.argv.slice(2)
  const i = args.indexOf('--near-miss')
  if (i !== -1) {
    const category = args[i + 1]
    const entry = args[i + 2] && !args[i + 2].startsWith('--') ? args[i + 2] : undefined
    const cfg = readConfig()
    if (!cfg?.share_near_misses) return
    const r = await sendNearMiss({ category, entry })
    if (!r.ok && !(r.status >= 400 && r.status < 500 && r.status !== 429)) queueNearMiss({ category, entry })
    return
  }
  await flush({ force: args.includes('--force') })
}

main().catch(() => {
  /* fail open: the next flush will try again */
})

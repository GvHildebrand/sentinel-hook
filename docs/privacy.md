# Privacy — sentinel-hook and the Vigilia witness

> Also published at https://aivigilia.com/witness/privacy. Last updated 25 September 2026.

## What leaves your machine

Only two kinds of message, and only these fields:

1. **A seal**, sent at most about once a minute while you work, and when a session ends:
   - your install's **public key** (the private key never leaves your machine);
   - a **fingerprint** of your record: the hash of its latest line. Each line carries a random value,
     so the fingerprint cannot be traced back to any command, file or text;
   - a **count**: how many lines your record has;
   - a **timestamp** and a **signature** made with your key.
2. **A near-miss** — only if you turn it on (`near-miss --auto on`, gate mode) or send one yourself
   (`near-miss <category>`). It carries your public key, one of five words
   (`destructive_command`, `credential_exposure`, `unreviewed_push`, `injection_suspected`,
   `other`), optionally the hash of the record line it refers to, a timestamp and a signature. No
   free text, ever.

**Never sent:** your code, file contents, commands, prompts, file paths, working directory, repository
names, tool names or arguments, outputs, hostname, username, git email, which agent you use, or
session ids. The requests carry a `user-agent: sentinel-hook/<version>` header and a content type, and
nothing else: no cookies, no identifiers.

The record itself — every line — stays in `~/.vigilia/` on your machine. You can read it, verify it,
and delete it.

## What is opt-in

- **Using the witness at all.** `init --offline`, `VIGILIA_WITNESS=off`, or `"witness": false` in
  `~/.vigilia/config.json` keeps everything local; nothing is sent.
- **Near-misses.** Off by default.
- **The weekly digest.** An Atom feed at your receipt page's address. Subscribing to it is the opt-in;
  there is no email and no account.

## What the witness keeps, and where

- The seals and near-misses it receives, to count them per install and to show you your receipt page.
- Its own hash chain, which lists per entry only a position, a time (to the second), and hashes. It
  says nothing about any install and is **public**.
- Hosting: a server in **Geneva, Switzerland, on Infomaniak** infrastructure, with backups on
  Infomaniak object storage in Switzerland.

Once in a while, one combined fingerprint of the witness's whole chain (the chain head) is also
**mirrored publicly**, to a GitHub repository and the Sigstore Rekor transparency log, so that no
single host, including us, can rewrite the history afterwards. Periodic snapshots to Zenodo are
planned and not running yet.

**IP addresses.** The server sees your IP address because that is how a reply reaches you. It uses it
in memory to limit how often one address can call, and never writes it anywhere — not to disk, not to
a log. The web server in front of it is configured with access logs off.

## Who can see what

- **Anyone:** the public chain (positions, times, hashes), and aggregate totals (how many installs, how
  many seals, near-misses by category).
- **Anyone who has your receipt page address:** how many actions your install recorded, how many
  seals, the date it was first seen, the time of the last seal, and near-miss categories if you
  reported any. The address is derived from your public key, which is not published; it is not
  guessable, but it is not secret once you share it. The page asks search engines not to index it.
- **Vigilia, as operator:** the seals and near-misses above. Nothing else exists to see.

## What we will never do

- Sell any of it.
- Publish anything about an install. What is published is aggregated and anonymised: totals and
  categories across all installs.
- Ask for, or accept, your code, commands or prompts.

## Deleting

`npx @vigilia/sentinel-hook uninstall` removes the hooks. Your record, key and receipts stay on your
machine until you delete `~/.vigilia/` yourself. To have the seals and near-misses from your install
removed from the witness's private files, write to the address below with your install id. The public
chain cannot be edited without breaking it; it carries nothing that identifies your install.

## Who operates it

Operated by Gregorio von Hildebrand, Swiss citizen, pending incorporation of Vigilia as a Swiss
association. Vigilia is run by a disclosed autonomous AI system.

Contact: gregorio.vonhildebrand@aivigilia.com

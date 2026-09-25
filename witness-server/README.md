# witness-server

The witness that sentinel-hook seals to. One Node process, `node:http`, Node built-ins only, no
database: three append-only JSONL files and a key. What it accepts and why is in
[../docs/witness.md](../docs/witness.md); what it keeps, in plain language, in
[../docs/privacy.md](../docs/privacy.md).

## Run it locally

```bash
node witness-server/server.mjs                     # http://127.0.0.1:8787, data in ./data
node --test witness-server/test.mjs
npx @vigilia/sentinel-hook init --witness-url http://127.0.0.1:8787   # point an install at it
```

It imports `canonical`/`sha256` from `scripts/sentinel/ledger.mjs` and the ed25519 helpers from
`scripts/sentinel/keys.mjs`, so client and server can never disagree about what was signed. Deploy the
whole repository checkout, not this folder alone.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8787` | port to listen on |
| `HOST` | `127.0.0.1` | address to bind; keep it on loopback behind a reverse proxy |
| `DATA_DIR` | `./data` | the server key, `seals.jsonl`, `chain.jsonl`, `near-misses.jsonl` |
| `PUBLIC_URL` | `http://HOST:PORT` | used in links on receipt pages and feeds, e.g. `https://witness.aivigilia.com` |
| `TRUST_PROXY` | unset | `1` behind Caddy: rate-limit on the last `X-Forwarded-For` address instead of the proxy's |

## Endpoints

| | |
|---|---|
| `POST /v1/seal` | exactly `{v,pub,head,seq,ts,sig}`; signature, ±10 min clock, one seal per key per 10 s; returns a signed receipt; a lower `seq` is recorded and flagged `regress` |
| `POST /v1/near-miss` | exactly `{v,pub,category,entry?,ts,sig}`; five categories; signed; rate-limited |
| `GET /v1/head` | the latest chain entry, signed, with the server's public key |
| `GET /v1/chain?from=&to=` | public chain entries, at most 1,000 per page |
| `GET /v1/tally` | installs, seals, actions witnessed, near-misses by category |
| `GET /r/<install id>` | the receipt page (HTML, `noindex`, no referrer) |
| `GET /r/<install id>/feed.xml` | weekly Atom digest |

Bodies over 2 KB are refused. Per-IP token bucket (60, refilling one a second) on every request. The
addresses are held in memory for that and nothing else: the process writes no request log, and
prints one line at start-up.

## Files in `DATA_DIR`

| File | Public? | Contents |
|---|---|---|
| `server-ed25519.pem` | **secret** (0600) | the witness's signing key, generated on first start |
| `chain.jsonl` | public | `{i, t, leaf, prev, hash, sig}` per seal — nothing about any install |
| `seals.jsonl` | private (0600) | the full seals, to count per install and rebuild state on restart |
| `near-misses.jsonl` | private (0600) | `{t, pub, category, entry?}` |

On start the server rebuilds its state from these files; `chain.jsonl` is the authority, and a seal
line whose chain entry was never written (a crash between the two appends) is ignored. **Losing the
key** means a new witness identity: receipts already issued still verify against the old public key,
but the mirror's pinned key must be changed by a person, on the record. Back it up.

## Deploy note: a small Infomaniak VM in Geneva

Pre-launch. Every Infomaniak-specific detail below is marked **check at deploy time**: it was written
from documentation, not from a deployment.

1. **The VM.** A small instance in Infomaniak's Public Cloud, in a Geneva region (1 vCPU and 1–2 GB is
   plenty; Debian or Ubuntu LTS). *Check at deploy time: the flavour names, and which region code is
   Geneva.* Open ports 22 (restricted), 80 and 443 only.

2. **Node.** Node 22 LTS from the distribution's NodeSource or official tarball. A dedicated user:

   ```bash
   sudo useradd --system --home /srv/witness --shell /usr/sbin/nologin witness
   sudo mkdir -p /srv/witness/data && sudo chown -R witness: /srv/witness && sudo chmod 700 /srv/witness/data
   sudo -u witness git clone https://github.com/aivigilia/sentinel-hook /srv/witness/app
   ```

3. **systemd** — `/etc/systemd/system/witness.service`:

   ```ini
   [Unit]
   Description=Vigilia witness
   After=network-online.target

   [Service]
   User=witness
   WorkingDirectory=/srv/witness/app
   ExecStart=/usr/bin/node witness-server/server.mjs
   Environment=PORT=8787 HOST=127.0.0.1 DATA_DIR=/srv/witness/data
   Environment=PUBLIC_URL=https://witness.aivigilia.com TRUST_PROXY=1
   Restart=on-failure
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/srv/witness/data
   PrivateTmp=true
   # journald keeps the one start-up line; the server logs nothing per request.

   [Install]
   WantedBy=multi-user.target
   ```

   `sudo systemctl enable --now witness`

4. **Caddy for TLS**, access logs off so no address is stored — `/etc/caddy/Caddyfile`:

   ```caddyfile
   {
       # No global `log` directive for access logs; Caddy writes none unless a site asks for one.
   }

   witness.aivigilia.com {
       reverse_proxy 127.0.0.1:8787
       # Deliberately no `log` directive here: an access log would record client IPs.
       header -Server
   }
   ```

   Caddy writes access logs only for sites with a `log` directive; keep it absent. *Check at deploy
   time* that the distribution's packaged Caddyfile or any imported snippet does not add one, and that
   Caddy's own runtime log level does not include request lines. DNS: an `A`/`AAAA` record for
   `witness.aivigilia.com` pointing at the VM.

5. **Backups to Infomaniak object storage (S3-compatible) with rclone.** *Check at deploy time:* the
   endpoint (documentation read on 2026-09-24 gives `https://s3.pub1.infomaniak.cloud`, provider
   `Other`, region `us-east-1`; see https://docs.infomaniak.cloud/object_storage/s3/), that the bucket
   is in Switzerland, and the credential flow (EC2-style keys from the OpenStack project).

   ```ini
   # /srv/witness/.config/rclone/rclone.conf  (0600, owned by witness)
   [ik]
   type = s3
   provider = Other
   endpoint = https://s3.pub1.infomaniak.cloud
   region = us-east-1
   access_key_id = …
   secret_access_key = …
   ```

   ```cron
   # crontab -u witness -e — every 15 minutes, append-only files, versioned bucket recommended
   */15 * * * * rclone copy /srv/witness/data ik:vigilia-witness/data --exclude server-ed25519.pem --quiet
   ```

   The key is **not** in that sync. Back it up once, separately: encrypted (`age` or `gpg`) to a
   second location a person controls, with its public half recorded in the mirror repository. A
   witness whose key can be restored by whoever holds the bucket is a weaker witness.

6. **The mirror.** Copy `templates/witness-mirror.yml` into the repository that keeps the public
   mirror, set `WITNESS_SERVER_PUB` to the key `GET /v1/head` reports, and let it run every six hours.

7. **Check.** `curl https://witness.aivigilia.com/healthz`, then `init --witness-url https://witness.aivigilia.com`
   on a test machine, `status`, and the receipt page. Confirm `journalctl -u witness` has one line and
   Caddy has no access log.

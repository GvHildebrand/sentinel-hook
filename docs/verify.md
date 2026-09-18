# Verifying a sealed record

Every attestation is four files under `research/sentinel/attestations/`, sharing a stamp:

- `<stamp>.json` — the attestation: the manifest, the Rekor log index and integrated time, the RFC 3161
  timestamp fields, and the two verification commands.
- `<stamp>.manifest.json` — the manifest that was signed: one entry per ledger with its sha256, line
  count and chain head.
- `<stamp>.sigstore.json` — the Sigstore bundle (signature, certificate, proof of log inclusion).
- `<stamp>.tsr` — the RFC 3161 timestamp reply.

## 1. The signature and the transparency log

```bash
cosign verify-blob <stamp>.manifest.json --bundle <stamp>.sigstore.json \
  --certificate-identity-regexp '^https://github.com/GvHildebrand/vigilia/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This confirms that exactly this manifest was signed by that repository's GitHub Actions workflow and
that the entry is in Rekor. The log index in the attestation can be opened at
`https://search.sigstore.dev/?logIndex=<index>`.

## 2. The independent timestamp

```bash
openssl ts -reply -in <stamp>.tsr -text            # shows the time and the authority
openssl ts -verify -data <stamp>.manifest.json -in <stamp>.tsr -CAfile digicert-tsa-chain.pem
```

The chain file is DigiCert's public timestamping chain; the `-cert` flag in the request makes the
reply carry its certificate, and `-text` shows which authority answered.

## 3. The chain heads

```bash
node -e "import('./scripts/sentinel/ledger.mjs').then(m => console.log(m.verify('research/sentinel/ledger/<identity>.jsonl')))"
```

Compare `head` with the manifest's `head` for that file. If the ledger has grown since the
attestation, verify that the attested head is a line in the file: every line's `hash` is its own
identity, and the chain from the first line to that hash must be unbroken.

## What this proves, and what it does not

It proves that a ledger with these hashes existed no later than the two timestamps, that its chain
was intact then, and that the workflow of that repository sealed it. It does not prove the rules
were right, or that no unhooked session ran alongside. A session that ran without the hook has no
heartbeat in any ledger; that absence is what the record makes visible.

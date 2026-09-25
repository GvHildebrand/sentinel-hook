# Verifying a sealed record

This page is about records sealed by the attestation workflow (`templates/sentinel-attest.yml`), the
way a repository checkout of the gate is sealed. An install made with `npx @vigilia/sentinel-hook init`
is sealed with the witness instead: `npx @vigilia/sentinel-hook verify` checks it, and
[witness.md](witness.md#checking-it-yourself) says how a third party can. The witness's own chain head
is sealed the same way as below, by `templates/witness-mirror.yml`.

Every attestation is four files under `research/sentinel/attestations/`, sharing a stamp:

- `<stamp>.json` — the attestation: the manifest, the Rekor log index and integrated time, the RFC 3161
  timestamp fields, which repository sealed it (`verify.sealed_by`), and the two verification commands.
- `<stamp>.manifest.json` — the manifest that was signed: one entry per ledger with its sha256, line
  count and chain head.
- `<stamp>.sigstore.json` — the Sigstore bundle (signature, certificate, proof of log inclusion).
- `<stamp>.tsr` — the RFC 3161 timestamp reply.

**Whose seal is it?** The attestations shipped in this repository were produced by the workflow of
Vigilia's fleet repository, `GvHildebrand/vigilia`, because that is where the sentinel runs; the
certificate identity therefore names that repository, not this one. When you run the workflow
template in your own repository, your attestations name yours.

## 0. Tools

- cosign: https://docs.sigstore.dev/cosign/system_config/installation/ (a single binary; `brew install cosign` on a Mac).
- openssl with the `ts` command (LibreSSL on macOS and OpenSSL on Linux both have it).
- DigiCert's root certificates, for the timestamp chain: https://www.digicert.com/kb/digicert-root-certificates.htm
  (the reply was requested with `-cert`, so it carries the signing certificate; the root is what you
  must trust yourself).

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
openssl ts -reply -in <stamp>.tsr -text            # shows the time, the policy and the serial
openssl ts -verify -data <stamp>.manifest.json -in <stamp>.tsr -CAfile digicert-tsa-chain.pem
```

`digicert-tsa-chain.pem` is the DigiCert root (and, if your openssl wants it, the intermediate)
concatenated from the page above.

## 3. The chain heads

```bash
node -e "import('./scripts/sentinel/ledger.mjs').then(m => console.log(m.verify('research/sentinel/ledger/<identity>.jsonl')))"
```

`ok: true` means every line's `prev` and `hash` check out; a file that does not exist answers
`ok: false, why: "missing"`. Compare `head` with the manifest's `head` for that file. If the ledger
has grown since the attestation, verify that the attested head is a line in the file: every line's
`hash` is its own identity, and the chain from the first line to that hash must be unbroken.

## What this proves, and what it does not

It proves that a ledger with these hashes existed no later than the two timestamps, that its chain
was intact then, and that the workflow of that repository sealed it. It does not prove the rules
were right, or that no unhooked session ran alongside. A session that ran without the hook has no
heartbeat in any ledger; that absence is what the record makes visible.

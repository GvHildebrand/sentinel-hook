/**
 * keys.mjs — the install's ed25519 key.
 *
 * Generated on this machine, on first run, with node:crypto. The private key is written to
 * `~/.vigilia/keys/ed25519.pem` with mode 0600 in a 0700 directory and never leaves it: the
 * witness never generates, holds or sees it. What the witness learns is the raw public key, which
 * is how it tells one install's seals from another's, and the install id is derived from it
 * (first 32 hex characters of its sha256), so the receipt URL names nothing about the person.
 *
 * Signatures are over the canonical JSON of the message without `sig` — the same canonical form
 * the ledger uses — so client and server can never disagree about what was signed.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { canonical, sha256 } from './ledger.mjs'
import { ensureDir } from './home.mjs'

export function b64url(buf) {
  return Buffer.from(buf).toString('base64url')
}

/** Load the key at `file`, generating it first if absent. Returns { privateKey, publicKey, pub, installId }. */
export function ensureKey(file) {
  ensureDir(path.dirname(file), 0o700)
  if (!existsSync(file)) {
    const { privateKey } = generateKeyPairSync('ed25519')
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
    // 'wx': if two processes race on first run, the second one reads the first one's key.
    try {
      writeFileSync(file, pem, { mode: 0o600, flag: 'wx' })
    } catch (err) {
      if (err?.code !== 'EEXIST') throw err
    }
  }
  return loadKey(file)
}

export function loadKey(file) {
  if (!existsSync(file)) return null
  const privateKey = createPrivateKey(readFileSync(file, 'utf8'))
  const publicKey = createPublicKey(privateKey)
  const pub = rawPublic(publicKey)
  return { privateKey, publicKey, pub, installId: installIdOf(pub) }
}

/** base64url of the 32-byte raw ed25519 public key. */
export function rawPublic(publicKey) {
  return publicKey.export({ format: 'jwk' }).x
}

export function publicFromRaw(pub) {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pub }, format: 'jwk' })
}

export function installIdOf(pub) {
  return sha256(Buffer.from(pub, 'base64url')).slice(0, 32)
}

/** Sign `msg` (its `sig` field, if any, excluded). Returns base64url. */
export function signMessage(privateKey, msg) {
  const { sig, ...body } = msg
  return b64url(edSign(null, Buffer.from(canonical(body)), privateKey))
}

/** Verify `msg.sig` over the canonical JSON of `msg` without `sig`, against raw public key `pub`. */
export function verifyMessage(pub, msg) {
  try {
    const { sig, ...body } = msg
    if (typeof sig !== 'string') return false
    return edVerify(null, Buffer.from(canonical(body)), publicFromRaw(pub), Buffer.from(sig, 'base64url'))
  } catch {
    return false
  }
}

/** Sign / verify a plain string (the witness signs each chain entry's hash this way). */
export function signString(privateKey, s) {
  return b64url(edSign(null, Buffer.from(String(s)), privateKey))
}

export function verifyString(pub, s, sig) {
  try {
    return edVerify(null, Buffer.from(String(s)), publicFromRaw(pub), Buffer.from(String(sig), 'base64url'))
  } catch {
    return false
  }
}

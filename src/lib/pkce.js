import { randomBytes, createHash } from 'node:crypto'
import { PKCE_VERIFIER_BYTES } from '../config.js'

function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

/**
 * Generate a fresh PKCE pair.
 *
 * verifier: 43-128 chars base64url (we emit ~64 chars)
 * challenge: base64url(SHA256(verifier))
 */
export function generatePkcePair() {
  const verifier = base64url(randomBytes(PKCE_VERIFIER_BYTES))
  const challenge = base64url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge, method: 'S256' }
}

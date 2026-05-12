// Resolve VION API base URL with the following precedence:
//   1. CLI flag (--api-url)
//   2. env VION_API_URL
//   3. default https://app.vionsec.com.br
//
// Allowing override is the standard for mature CLIs (vercel, stripe). It
// unlocks dev/staging without forking the codebase.

export const DEFAULT_API_URL = 'https://app.vionsec.com.br'

export function resolveApiUrl(flagValue) {
  const raw = flagValue || process.env.VION_API_URL || DEFAULT_API_URL
  // Strip trailing slash for consistent path joining.
  return raw.replace(/\/+$/, '')
}

// PKCE constants
export const PKCE_VERIFIER_BYTES = 48 // 384 bits → ~64 chars base64url
export const CODE_HEX_LEN = 64

export const SUPPORTED_CLIS = ['claude', 'blackbox', 'codex', 'terminal']

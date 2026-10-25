/**
 * Test fixtures for secret-detector tests.
 * All values are clearly fake/test-only to avoid false positives in scanners.
 */

// AWS
export const FAKE_AWS_KEY = 'AKIA1234567890ABCDEF'

// Private keys
export const FAKE_RSA_HEADER = '-----BEGIN RSA PRIVATE KEY-----'
export const FAKE_EC_HEADER = '-----BEGIN EC PRIVATE KEY-----'
export const FAKE_PK_HEADER = '-----BEGIN PRIVATE KEY-----'

// JWT
export const FAKE_JWT_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0'

// API keys
export const FAKE_API_KEY = 'sk_live_1234567890abcdef'

// Generic secrets
export const FAKE_PASSWORD = 'TEST_SuperSecretPassword123'
export const FAKE_SECRET = 'TEST_my_ultra_secret_value'
export const FAKE_TOKEN = 'TEST_abcdefghijklmnop'

// Env var values
export const FAKE_ENV_API_KEY = 'TEST_my_super_long_api_key_value'
export const FAKE_ENV_AWS_SECRET = 'TEST_abcdefghijklmnopqrst'
export const FAKE_ENV_PASSWORD = 'TEST_supersecretpassword'

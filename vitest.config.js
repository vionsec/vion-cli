import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/__tests__/**/*.test.js', 'tests/**/*.test.js'],
    pool: 'forks',
    testTimeout: 30000,
  },
})

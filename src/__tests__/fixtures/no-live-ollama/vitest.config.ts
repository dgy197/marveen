import { defineConfig } from 'vitest/config'

// Config of the NESTED vitest runs in no-live-ollama-gate.test.ts, never of the
// main suite: only the fixture tests below, and only the no-live-ollama gate as
// setup. FIXTURE_WITHOUT_GATE=1 drops the gate, which is the positive control
// (the same fixture then really reaches its endpoint).
export default defineConfig({
  test: {
    include: ['src/__tests__/fixtures/no-live-ollama/*.fixture.ts'],
    setupFiles: process.env.FIXTURE_WITHOUT_GATE === '1' ? [] : ['./src/__tests__/setup/no-live-ollama.ts'],
    testTimeout: 20_000,
  },
})

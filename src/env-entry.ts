// What the .env writer accepts (card fec6335f, BE-3 round 2; taken over for
// card 053f4e66, where a forged line could flip FLEET_IMPORT_APPLY_ENABLED or
// MAIN_CHANNEL_ADMIN_ENABLED). Kept apart from
// env.ts so a caller can check an entry before it writes anything, and so a
// test that mocks env.js still gets the real check.
//
// A key must be a plain variable name; a value must not hold CR, LF or NUL.
// Otherwise one entry could forge a second line (`x\nCREDIT_GATE_MODE=off`)
// or slip past an exact-match deny list (`CREDIT_GATE_MODE `).

export const ENV_KEY_RE = /^[A-Z_][A-Z0-9_]*$/

/** Refused .env entry; the message names the key and the rule, never the value. */
export class InvalidEnvEntryError extends Error {
  constructor(readonly key: string, readonly rule: 'key' | 'value') {
    super(rule === 'key'
      ? `.env: the key ${JSON.stringify(key.slice(0, 64))} is not a plain variable name (^[A-Z_][A-Z0-9_]*$)`
      : `.env: the value of ${JSON.stringify(key.slice(0, 64))} holds a line break or NUL`)
    this.name = 'InvalidEnvEntryError'
  }
}

/** null when the entry may be written, else which part breaks the rule. */
export function envEntryProblem(key: string, value: string): 'key' | 'value' | null {
  if (typeof key !== 'string' || !ENV_KEY_RE.test(key)) return 'key'
  if (typeof value !== 'string' || /[\r\n\0]/.test(value)) return 'value'
  return null
}

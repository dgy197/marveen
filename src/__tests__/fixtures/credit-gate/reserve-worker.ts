// One "process" of the credit-gate concurrency test (card fec6335f, N2a K3).
// Started twice, at the same time, by credit-gate-procs.test.ts:
//   node --require loopback-guard.cjs --import tsx reserve-worker.ts \
//     <dbPath> <storeDir> <nowMs> <startAtMs> <attempts> <tag> <calibration JSON>
// It opens its OWN connection to the shared SQLite file, waits for the common
// start instant, then reserves 1 USD batches as fast as it can and prints one
// JSON line with what it got. No network, no real store: everything is under
// the test's tmp directory.

import Database from 'better-sqlite3'
import { join } from 'node:path'
import { loadCreditGateConfigFile, readCreditGateMode, readProtectedFile } from '../../../web/credit-gate/config.js'
import { CreditGate, type Calibration } from '../../../web/credit-gate/gate.js'
import { loadPricing } from '../../../web/credit-gate/pricing.js'

const [dbPath, storeDir, nowArg, startArg, attemptsArg, tag, calJson] = process.argv.slice(2)
const nowMs = Number(nowArg)
const startAt = Number(startArg)
const attempts = Number(attemptsArg)
const cal = JSON.parse(calJson) as Calibration

const db = new Database(dbPath, { timeout: 15_000 })
db.pragma('journal_mode = WAL')
const gate = new CreditGate({
  db,
  mode: readCreditGateMode('enforce'),
  loadConfig: () => loadCreditGateConfigFile(join(storeDir, 'credit-gate', 'config.json')),
  loadPricing: (n) => {
    const r = readProtectedFile(join(storeDir, 'credit-gate', 'pricing.json'))
    return r.ok ? loadPricing(r.text, n) : r
  },
  calibration: () => cal,
  guardEventsPath: join(storeDir, 'interactive-key-guard-events.jsonl'),
  now: () => nowMs,
})

const readyAt = Date.now()
while (Date.now() < startAt) {
  // spin: both processes leave this loop at the same instant
}
const started = Date.now()
let ok = 0
const reasons: Record<string, number> = {}
for (let i = 0; i < attempts; i++) {
  const r = gate.reserve({
    kind: 'batch', model: 'claude-haiku-5-5', input_tokens_total: 1_000_000, max_output_tokens_total: 0, request_count: 1, caller: `proc-${tag}`,
  })
  if ('ok' in r && r.ok) ok++
  else {
    const reason = 'reason' in r ? r.reason : 'not_enforced'
    reasons[reason] = (reasons[reason] ?? 0) + 1
  }
}
const ended = Date.now()
db.close()
process.stdout.write(JSON.stringify({ tag, pid: process.pid, readyAt, started, ended, ok, reasons }) + '\n')
process.exit(0)

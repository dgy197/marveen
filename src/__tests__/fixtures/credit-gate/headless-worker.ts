// A stand-in dashboard process for the headless-runner process tests (card
// fec6335f, N4a). credit-gate-headless-procs.test.ts starts it as
//   node --require loopback-guard.cjs --import tsx headless-worker.ts <spec.json>
// It opens its OWN connection to the test's SQLite file, builds the gate and
// the runner on the test's tmp store, starts ONE run of fake-claude.mjs, prints
// one `UP <json>` line once the fake is up (its pid and its grandchild's; the
// prefix, because the worker's own logs are JSON lines on stdout too), and
// then idles until the test signals or kills it. No network, no real store, no real
// key: the dummy key comes from a 0600 file in the test's tmp directory.

import Database from 'better-sqlite3'
import { spawn } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { loadCreditGateConfigFile, readCreditGateMode, readProtectedFile } from '../../../web/credit-gate/config.js'
import { CreditGate, type Calibration } from '../../../web/credit-gate/gate.js'
import { loadPricing } from '../../../web/credit-gate/pricing.js'
import { HeadlessRunner, type HeadlessRunRequest } from '../../../web/credit-gate/headless/runner.js'

interface Spec {
  dbPath: string
  storeDir: string
  nowMs: number
  cal: Calibration
  tmpRoot: string
  keyFile: string
  forbiddenRoots: string[]
  request: HeadlessRunRequest
  observe: string
  /** Install a SIGTERM listener of its own, like the dashboard's shutdown(). */
  ownShutdown?: boolean
  /** A fixed start time for a live pid instead of ps (sandbox-exec denies ps; N6). */
  fakeProcStart?: string
}

const spec = JSON.parse(readFileSync(process.argv[2], 'utf8')) as Spec
const db = new Database(spec.dbPath, { timeout: 15_000 })
db.pragma('journal_mode = WAL')
const gate = new CreditGate({
  db,
  mode: readCreditGateMode('enforce'),
  loadConfig: () => loadCreditGateConfigFile(join(spec.storeDir, 'credit-gate', 'config.json')),
  loadPricing: (n) => {
    const r = readProtectedFile(join(spec.storeDir, 'credit-gate', 'pricing.json'))
    return r.ok ? loadPricing(r.text, n) : r
  },
  calibration: () => spec.cal,
  guardEventsPath: join(spec.storeDir, 'interactive-key-guard-events.jsonl'),
  now: () => spec.nowMs,
})

if (spec.ownShutdown) {
  process.on('SIGTERM', () => {
    setTimeout(() => process.exit(0), 50)
  })
}

const runner: HeadlessRunner = new HeadlessRunner({
  db,
  gate,
  loadConfig: () => loadCreditGateConfigFile(join(spec.storeDir, 'credit-gate', 'config.json')),
  getKey: () => readFileSync(spec.keyFile, 'utf8'),
  approvedHash: () => runner.configHash(),
  forbiddenRoots: spec.forbiddenRoots,
  spawner: (file, args, options) => {
    if (!file.startsWith(spec.tmpRoot + '/')) throw new Error(`worker spawner: refusing ${file}`)
    return spawn(file, args, options)
  },
  now: () => spec.nowMs,
  killGraceMs: 300,
  installSignalHandlers: true,
  ...(spec.fakeProcStart === undefined ? {} : {
    procStart: (pid: number) => {
      try {
        process.kill(pid, 0)
        return spec.fakeProcStart as string
      } catch {
        return null
      }
    },
  }),
})

const r = runner.start(spec.request, { caller: 'ezermester' })
if (!r.ok) {
  process.stdout.write('UP ' + JSON.stringify({ error: r.reason, detail: r.detail ?? null }) + '\n')
  process.exit(3)
}
const t = setInterval(() => {
  if (!existsSync(spec.observe)) return
  const seen = JSON.parse(readFileSync(spec.observe, 'utf8')) as { pid: number; grandchild?: number }
  clearInterval(t)
  process.stdout.write('UP ' + JSON.stringify({ run_id: r.run_id, pid: seen.pid, grandchild: seen.grandchild ?? null, worker: process.pid }) + '\n')
}, 20)
setInterval(() => {}, 1000)

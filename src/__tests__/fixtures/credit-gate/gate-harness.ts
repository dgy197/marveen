// Test harness of the credit gate (card fec6335f, N2a). Everything lives in a
// fresh tmp directory: the store, the config and price files, a usage.jsonl,
// the batch STOP and the SQLite file. The real store, usage.jsonl and STOP are
// never touched (blueprint 6.3).

import Database from 'better-sqlite3'
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readCreditGateMode, type ModeReading } from '../../../web/credit-gate/config.js'
import { CreditGate, type Calibration, type CalibrationGrant } from '../../../web/credit-gate/gate.js'
import { CreditLedger } from '../../../web/credit-gate/ledger.js'
import type { PricingTable } from '../../../web/credit-gate/types.js'
import { fileGateDeps } from '../../../web/credit-gate/runtime.js'
import { asMicro, parseUsd } from '../../../web/credit-gate/money.js'
import { applyCreditGateSchema } from '../../../web/credit-gate/schema.js'
import type { StopFs } from '../../../web/credit-gate/stop-file.js'

/** The fake "now" of most tests: 2026-10-16 08:00:00Z. */
export const T0 = Date.UTC(2026, 9, 16, 8, 0, 0)
export const HOUR = 3_600_000
export const USD = 1_000_000

/** N0 prices (USD/MTok), batch discount 50%; Haiku has a long-context band. */
export function pricingText(verifiedAt = '2026-10-16'): string {
  return `{
  "schema": "credit-pricing/v1",
  "verified_at": "${verifiedAt}",
  "sources": [{"url": "https://platform.claude.com/docs/en/about-claude/pricing", "retrieved_at": "2026-10-16"}],
  "batch_discount_pct": 50,
  "models": [
    {"ids": ["claude-opus-5-5"], "input": "4.00", "output": "20.00", "cache_write_5m": "5.00", "cache_write_1h": "8.00", "cache_read": "0.20", "long_context": null},
    {"ids": ["claude-sonnet-5-5"], "input": "2.00", "output": "10.00", "cache_write_5m": "2.50", "cache_write_1h": "4.00", "cache_read": "0.10", "long_context": null},
    {"ids": ["claude-haiku-5-5"], "input": "0.10", "output": "0.50", "cache_write_5m": "0.125", "cache_write_1h": "0.20", "cache_read": "0.01",
     "long_context": {"threshold_input_tokens": 100000, "input": "0.50", "output": "2.50", "cache_write_5m": "0.625", "cache_write_1h": "1.00", "cache_read": "0.05"}}
  ]
}`
}

export interface ConfigOver {
  thresholds?: Record<string, unknown>
  [k: string]: unknown
}

export function configObject(usagePath: string, stopPath: string, over: ConfigOver = {}): Record<string, unknown> {
  const { thresholds, ...rest } = over
  return {
    schema: 'credit-gate-config/v1',
    ledgerSources: [{ id: 'anthropic-batch', path: usagePath, format: 'usage-jsonl-v1' }],
    stopFile: stopPath,
    thresholds: { tClose: '20.00', tLowcal: '60.00', tReopen: '50.00', tCloseLowcalFallback: '40.00', lowcalWaitH: 12, ...thresholds },
    expiryMarginH: 2,
    batchHorizonH: 24,
    refreshS: 30,
    maxLedgerAgeS: 120,
    reservationFactor: '1.5',
    protected: { R: '3.63', V: '10.00' },
    calibrationMaxAgeH: 24,
    vaultKeyId: 'ANTHROPIC_API_KEY_BATCH',
    headless: {
      allowedCallers: ['ezermester'], cwdRoots: ['/Volumes/8T/10_LOCAL/Brainy'], forbiddenCwds: ['/Users/x/marveen'],
      runsDir: '/tmp/credit-gate-runs', claudeBin: '/opt/homebrew/bin/claude', claudeBinSha256: 'a'.repeat(64), models: ['claude-opus-5-5', 'claude-sonnet-5-5'],
      maxBudgetUsd: '5.00', wallClockMin: 90,
    },
    ...rest,
  }
}

function usd(s: string) {
  const m = parseUsd(s)
  if (m === null) throw new Error(`bad USD fixture ${s}`)
  return m
}

export function grant(granted: string, expires: string, original: string, remaining: string): CalibrationGrant {
  return { granted, expires, original_micro: usd(original), remaining_micro: usd(remaining) }
}

/** A calibration (what N2c will produce from an owner-approved reading). */
export function calibration(id: number, grants: CalibrationGrant[], over: Partial<Calibration> = {}): Calibration {
  return {
    id,
    captured_at_lb_ms: T0 - 2 * HOUR,
    grants,
    protected: { R_micro: usd('3.63'), V_micro: usd('10.00') },
    ...over,
  }
}

/** One Team grant with `remaining` USD left, expiring 2026-11-17. */
export function simpleCal(id: number, remaining: string, over: Partial<Calibration> = {}): Calibration {
  return calibration(id, [grant('2026-10-14', '2026-11-17', '200.00', remaining)], over)
}

/** One usage.jsonl line the way Python's json.dumps writes it. */
export function pyLine(o: Record<string, unknown>): string {
  return '{' + Object.entries(o).map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(', ') + '}\n'
}

export interface HarnessOptions {
  mode?: string
  config?: ConfigOver
  pricingVerifiedAt?: string
  cal?: Calibration | null
  now?: number
  stopFs?: StopFs
}

export class Harness {
  readonly dir: string
  readonly storeDir: string
  readonly gateDir: string
  readonly usagePath: string
  readonly batchDir: string
  readonly stopPath: string
  readonly guardPath: string
  readonly dbPath: string
  readonly db: Database.Database
  readonly extraDbs: Database.Database[] = []
  now: number
  cal: Calibration | null
  mode: ModeReading
  gate: CreditGate
  stopFs: StopFs | undefined
  /** Called whenever any gate of this harness reads the calibration source. */
  onCalibrationRead: (() => void) | null = null
  /** Ledger methods (by name) that throw a RangeError while listed (BE-2 fault tests). */
  readonly ledgerThrows = new Set<string>()
  /** Building a ledger throws while set. */
  ledgerInitThrows = false
  /** Loading the price table throws while set. */
  pricingThrows = false
  /** The loaded table throws on any model lookup while set. */
  tableThrows = false

  constructor(o: HarnessOptions = {}) {
    this.dir = mkdtempSync(join(tmpdir(), 'credit-gate-'))
    this.storeDir = join(this.dir, 'store')
    this.gateDir = join(this.storeDir, 'credit-gate')
    mkdirSync(this.gateDir, { recursive: true, mode: 0o700 })
    chmodSync(this.storeDir, 0o700)
    chmodSync(this.gateDir, 0o700)
    this.usagePath = join(this.dir, 'usage.jsonl')
    writeFileSync(this.usagePath, '')
    this.batchDir = join(this.dir, 'batch')
    mkdirSync(this.batchDir)
    this.stopPath = join(this.batchDir, 'STOP')
    this.guardPath = join(this.storeDir, 'interactive-key-guard-events.jsonl')
    this.dbPath = join(this.dir, 'gate.sqlite')
    this.db = new Database(this.dbPath)
    this.db.pragma('journal_mode = WAL')
    applyCreditGateSchema(this.db)
    this.now = o.now ?? T0
    this.cal = o.cal === undefined ? null : o.cal
    this.mode = readCreditGateMode(o.mode ?? 'enforce')
    this.stopFs = o.stopFs
    this.writeConfig(o.config ?? {})
    this.writePricing(o.pricingVerifiedAt ?? '2026-10-16')
    this.gate = this.makeGate()
  }

  makeGate(db: Database.Database = this.db, mode: ModeReading = this.mode): CreditGate {
    const deps = fileGateDeps({
      storeDir: this.storeDir,
      db,
      mode,
      calibration: () => {
        this.onCalibrationRead?.()
        return this.cal
      },
      now: () => this.now,
      stopFs: this.stopFs,
    })
    return new CreditGate({
      ...deps,
      loadPricing: (n) => {
        if (this.pricingThrows) throw new RangeError('injected pricing fault')
        const r = deps.loadPricing(n)
        return r.ok && this.tableThrows ? { ok: true, table: throwingTable(r.table) } : r
      },
      ledgerFactory: (ldb, opts) => {
        if (this.ledgerInitThrows) throw new RangeError('injected ledger construction fault')
        return faultyLedger(new CreditLedger(ldb, opts), this.ledgerThrows)
      },
    })
  }

  /** A second connection to the same database file (another process's view). */
  openDb(timeoutMs = 5000): Database.Database {
    const db = new Database(this.dbPath, { timeout: timeoutMs })
    db.pragma('journal_mode = WAL')
    this.extraDbs.push(db)
    return db
  }

  writeConfig(over: ConfigOver = {}): void {
    const p = join(this.gateDir, 'config.json')
    writeFileSync(p, JSON.stringify(configObject(this.usagePath, this.stopPath, over), null, 2), { mode: 0o600 })
    chmodSync(p, 0o600)
  }

  writePricing(verifiedAt: string): void {
    const p = join(this.gateDir, 'pricing.json')
    writeFileSync(p, pricingText(verifiedAt), { mode: 0o600 })
    chmodSync(p, 0o600)
  }

  /** Append one synchronous usage row (batch_client.py shape). */
  usage(model: string, input: number, output: number, tsS = Math.floor((T0 - HOUR) / 1000)): void {
    appendFileSync(this.usagePath, pyLine({ ts: tsS, month: '2026-10', caller: 'test', model, in: input, out: output }))
  }

  /** Append one batch result row (message_batches.py shape). */
  batchUsage(batchId: string, customId: string, model: string, input: number, output: number, tsS = Math.floor((T0 - HOUR) / 1000)): void {
    appendFileSync(this.usagePath, pyLine({
      ts: tsS, month: '2026-10', caller: 'test', model, in: input, out: output,
      cache_creation_input_tokens: 0, cache_read_input_tokens: 0, batch_id: batchId, custom_id: customId, api: 'message_batches',
    }))
  }

  state(): Record<string, unknown> {
    return this.db.prepare('SELECT * FROM credit_gate_state WHERE id = 1').get() as Record<string, unknown>
  }

  events(kind?: string): Array<Record<string, unknown>> {
    return (kind
      ? this.db.prepare('SELECT * FROM credit_gate_events WHERE kind = ? ORDER BY id').all(kind)
      : this.db.prepare('SELECT * FROM credit_gate_events ORDER BY id').all()) as Array<Record<string, unknown>>
  }

  reservations(): Array<Record<string, unknown>> {
    return this.db.prepare('SELECT * FROM credit_reservations ORDER BY created_at, id').all() as Array<Record<string, unknown>>
  }

  batchDirEntries(): string[] {
    return readdirSync(this.batchDir).sort()
  }

  cleanup(): void {
    for (const d of this.extraDbs) {
      try { d.close() } catch { /* already closed */ }
    }
    try { this.db.close() } catch { /* already closed */ }
    rmSync(this.dir, { recursive: true, force: true })
  }
}

export const micro = (n: number) => asMicro(n)

/** A real ledger whose listed methods throw while their name is in `throws`. */
function faultyLedger(real: CreditLedger, throws: ReadonlySet<string>): CreditLedger {
  return new Proxy(real, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver)
      if (typeof v !== 'function') return v
      return (...args: unknown[]) => {
        if (throws.has(String(prop))) throw new RangeError(`injected ledger fault in ${String(prop)}`)
        return (v as (...a: unknown[]) => unknown).apply(target, args)
      }
    },
  })
}

/** A price table whose model lookup throws. */
function throwingTable(t: PricingTable): PricingTable {
  const byId = new Proxy(t.byId, {
    get(target, prop) {
      if (prop === 'get') return () => { throw new RangeError('injected price table fault') }
      const v = Reflect.get(target, prop, target)
      return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(target) : v
    },
  })
  return { ...t, byId }
}

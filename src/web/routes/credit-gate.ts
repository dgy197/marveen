// The credit gate's HTTP API (card fec6335f, blueprint 4.2): the status, the
// batch reservation and the signal endpoints (node N2a), and the headless
// runs (node N4b): POST /runs, GET /runs/:id, POST /runs/:id/cancel.
//
// Bearer auth is done by the dispatcher in web.ts (every /api/* path). The
// answers never carry a secret: money as decimal USD strings, reasons as
// fixed words; a run's answer never carries its prompt or the key.
//
// Off mode (CREDIT_GATE_MODE missing, the default) answers {enforced:false}
// to every reservation call BEFORE looking at the body, so the batch client
// keeps today's path exactly; shadow mode does the same for reservations
// (blueprint 3.1). Runs: 409 gate_off / gate_shadow.
//
// Who may run (blueprint 11.6): the caller is the X-Agent-Id claim the auth
// gate put in ctx.auth -- and only that; it must be on headless.allowedCallers.
// The whole fleet shares ONE Bearer token, so the token does not tell who is
// calling, and the claim is a label anyone can type: this stops an accidental
// caller, not a deliberate one. What bounds the spending is the gate.
//
// A run (N4b): the body is checked here (400), the caller and the request by
// the runner's precheck (validateCwd, the model list, the budget maximum),
// the gate must be OPEN with no canary window open (K-01, N7B1: from a
// canary's admission until its after-reading is recorded), and a canary needs no other
// reservation of any kind open or unknown (409, BE-4b); then a normal run needs
// the hash a canary approved, a canary the owner's credit_gate_canary
// approval: the route takes a run id from the runner first, N2c's
// consumeCanaryApproval consumes the approval for exactly this config hash,
// model, budget, run id, node, cwd and prompt (BE-4b P6: the approval names
// its run, so another Bearer holder cannot spend it on its own prompt), and
// the runner then takes the hash from the
// consumed approval's row, once, for that run only (takeCanaryHash) -- never
// from the request (a config_hash in the body is refused). Everything that
// can refuse for free runs BEFORE the consume, so a bad request does not
// spend the approval. Under the grant model (card 40e03382) `canary_approval_id`
// is the owner's credit_gate_enforce approval: the same consume call binds the
// run to that button's canary row (no new approval, once; the old
// credit_gate_canary approval is refused there), and the status answer carries
// the model's `grant_model` block.
//
// GET and cancel of a run (B7): its own caller is served before the config is
// asked, so a live run stays visible and stoppable when the config goes
// invalid or drops the caller mid-run; anyone else gets checkCaller's 409 or
// a 404 -- exactly what an unknown id gets.

import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { logger } from '../../logger.js'
import { json, methodNotAllowed, readBody, RequestBodyTooLargeError } from '../http-helpers.js'
import { auditStatus } from '../credit-gate/audit.js'
import { formatUsd, SIGNAL_KINDS, type CreditGate, type OpResult, type SignalKind } from '../credit-gate/gate.js'
import { parseUsd } from '../credit-gate/money.js'
import { CONFIG_FILE, CREDIT_GATE_DIR, loadCreditGateConfigFile, PRICING_FILE } from '../credit-gate/config.js'
import { grantModelStatus, type GrantModelStatus } from '../credit-gate/grant-status.js'
import { getCreditGateRuntime, inactiveStatus, loadPricingFile, type CreditGateRuntime } from '../credit-gate/runtime.js'
import { getHeadlessRunner } from '../credit-gate/headless/reconcile.js'
import { approvedCanary } from '../credit-gate/calibration.js'
import { MAX_PROMPT_BYTES, type HeadlessRunner, type HeadlessRunRequest, type RunRecord, type StartContext } from '../credit-gate/headless/runner.js'
import { OPEN_RUN_STATUSES } from '../credit-gate/headless/schema-runs.js'
import type { RouteContext } from './types.js'

const PREFIX = '/api/credit-gate'
const MAX_BODY_BYTES = 16 * 1024
const RES_OP_RE = /^\/api\/credit-gate\/reservations\/([^/]+)\/(bind|complete|release)$/
const ID_RE = /^[A-Za-z0-9-]{1,64}$/
const MODEL_RE = /^[A-Za-z0-9_.-]{1,128}$/
const CALLER_RE = /^[A-Za-z0-9_.-]{1,64}$/
const SOURCE_RE = /^[A-Za-z0-9_.:-]{1,64}$/
const BATCH_ID_RE = /^msgbatch_[A-Za-z0-9_-]{1,160}$/
const MAX_TOKENS_TOTAL = 10_000_000_000
const MAX_REQUESTS = 100_000
/** A run's body: a 256 KB prompt, JSON-escaped (up to 6 bytes a byte), and the rest. */
const RUNS_MAX_BODY_BYTES = 2 * 1024 * 1024
const RUN_PATH_RE = /^\/api\/credit-gate\/runs\/([^/]+)(\/cancel)?$/
const RUN_ID_RE = /^[A-Za-z0-9_-]{1,64}$/
const NODE_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/
/** The runner's refusals that mean "this request is wrong" (400); any other is the gate's or the setup's (409). */
const RUN_BAD_REQUEST: ReadonlySet<string> = new Set([
  'request_invalid', 'node_id_invalid', 'model_not_allowed', 'effort_not_allowed', 'mode_invalid', 'budget_invalid', 'budget_over_max', 'prompt_invalid',
])

class BadRequest extends Error {
  constructor(readonly status: 400 | 413, message: string) {
    super(message)
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function intIn(v: unknown, min: number, max: number): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max
}

/** The body as a JSON object with exactly the allowed keys. */
async function readObject(
  ctx: RouteContext, required: readonly string[], optional: readonly string[] = [], emptyOk = false, maxBytes = MAX_BODY_BYTES,
): Promise<Record<string, unknown>> {
  let buf: Buffer
  try {
    buf = await readBody(ctx.req, { maxBytes })
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) throw new BadRequest(413, 'body too large')
    throw err
  }
  const text = buf.toString('utf8')
  if (text.trim() === '' && emptyOk) return {}
  let o: unknown
  try {
    o = JSON.parse(text)
  } catch {
    throw new BadRequest(400, 'body: not valid JSON')
  }
  if (!isPlainObject(o)) throw new BadRequest(400, 'body: must be a JSON object')
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) throw new BadRequest(400, `body: unknown field ${JSON.stringify(k)}`)
  }
  for (const k of required) {
    if (!Object.hasOwn(o, k)) throw new BadRequest(400, `body: ${k} is missing`)
  }
  return o
}

/** json() that reports the request as handled. */
function reply(res: RouteContext['res'], data: unknown, status = 200): true {
  json(res, data, status)
  return true
}

function opAnswer(ctx: RouteContext, r: OpResult): true {
  if (r.ok) return reply(ctx.res, { enforced: true, ok: true, status: r.status, changed: r.changed })
  return reply(ctx.res, { enforced: true, ok: false, reason: r.reason }, r.code)
}

// ---------------------------------------------------------------- runs (N4b)

/** The X-Agent-Id claim of a Bearer-token request; anything else has no caller. A label, not a credential (11.6). */
function callerOf(ctx: RouteContext): string | null {
  return ctx.auth?.kind === 'token' && typeof ctx.auth.agent === 'string' ? ctx.auth.agent : null
}

function runRefusalStatus(reason: string): 400 | 409 {
  return RUN_BAD_REQUEST.has(reason) || reason.startsWith('cwd_') ? 400 : 409
}

/** Why no run can be served at all right now; null = the runner is there. */
function runsUnavailable(mode: string, gate: CreditGate | null): string | null {
  if (mode === 'off') return 'gate_off'
  if (mode === 'shadow') return 'gate_shadow'
  if (!gate) return 'gate_not_running'
  return getHeadlessRunner() === null ? 'runs_unavailable' : null
}

/**
 * Blueprint 4.2 (N6): the hash the newest evaluated canary approved, the
 * runner's hash now, and whether a normal run may start under it (E-04).
 * Read-only; no gate, no table or no runner reads as null.
 */
function canaryView(rt: CreditGateRuntime): { approved_hash: string | null; current_hash: string | null; match: boolean } {
  let approved: string | null = null
  let current: string | null = null
  try {
    approved = rt.gate && rt.db ? approvedCanary(rt.db)?.config_hash ?? null : null
  } catch {
    approved = null
  }
  try {
    current = rt.gate ? getHeadlessRunner()?.configHash() ?? null : null
  } catch {
    current = null
  }
  return { approved_hash: approved, current_hash: current, match: approved !== null && approved === current }
}

/**
 * Card 40e03382 (N3): the grant model's numbers when the config selects it, in
 * every mode (the owner sees them before the button); null otherwise. Read-only.
 */
function grantModelView(rt: CreditGateRuntime): GrantModelStatus | null {
  try {
    const dir = join(rt.storeDir, CREDIT_GATE_DIR)
    return grantModelStatus(
      rt.db,
      loadCreditGateConfigFile(join(dir, CONFIG_FILE)),
      (nowMs) => loadPricingFile(join(dir, PRICING_FILE), nowMs),
      Date.now(),
    )
  } catch {
    return null
  }
}

function usdOrNull(micro: number | null): string | null {
  return micro === null ? null : formatUsd(micro)
}

function isoOrNull(ms: number | null): string | null {
  return ms === null ? null : new Date(ms).toISOString()
}

/** A run as the caller sees it: state, cost and result; never the prompt, the key or the run directory. */
function runView(r: RunRecord): Record<string, unknown> {
  const res = r.result ?? {}
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
  return {
    run_id: r.id,
    node_id: r.node_id,
    model: r.model,
    effort: r.effort,
    mode: r.mode,
    status: r.status,
    done: !(OPEN_RUN_STATUSES as readonly string[]).includes(r.status),
    started_at: isoOrNull(r.started_at),
    ended_at: isoOrNull(r.ended_at),
    exit_code: r.exit_code,
    signal: r.signal,
    reason: r.reason,
    budget_usd: formatUsd(r.budget_micro),
    est_usd: usdOrNull(r.est_micro),
    cli_usd: usdOrNull(r.cli_micro),
    basis: r.basis,
    is_error: typeof res.is_error === 'boolean' ? res.is_error : null,
    num_turns: num(res.num_turns),
    total_cost_usd: num(res.total_cost_usd),
    usage: typeof res.usage === 'object' && res.usage !== null && !Array.isArray(res.usage) ? res.usage : null,
    result_text: typeof res.result === 'string' ? res.result : null,
  }
}

async function startRun(ctx: RouteContext, rt: CreditGateRuntime, gate: CreditGate, runner: HeadlessRunner): Promise<true> {
  const { res } = ctx
  const b = await readObject(ctx, ['node_id', 'model', 'effort', 'budget_usd', 'cwd', 'prompt', 'mode'], ['canary_approval_id', 'config_hash'], false, RUNS_MAX_BODY_BYTES)
  const caller = callerOf(ctx)
  const callerRefusal = runner.checkCaller(caller)
  if (callerRefusal !== null) return reply(res, { reason: callerRefusal }, 409)
  // E-04: the hash is the approval's (a canary) or the canary verdict's (a normal run), never the caller's.
  if (Object.hasOwn(b, 'config_hash')) return reply(res, { reason: 'hash_not_approved', detail: 'config_hash_in_request' }, 409)
  if (typeof b.node_id !== 'string' || !NODE_ID_RE.test(b.node_id)) throw new BadRequest(400, 'node_id: 1-64 of A-Z a-z 0-9 _ . : -')
  if (typeof b.model !== 'string' || !MODEL_RE.test(b.model)) throw new BadRequest(400, 'model: not a model id')
  if (b.effort !== 'high' && b.effort !== 'xhigh') throw new BadRequest(400, 'effort: must be "high" or "xhigh"')
  const budget = parseUsd(b.budget_usd)
  if (typeof b.budget_usd !== 'string' || budget === null || budget <= 0) throw new BadRequest(400, 'budget_usd: a decimal string with exactly two decimals, above 0.00')
  if (typeof b.cwd !== 'string') throw new BadRequest(400, 'cwd: must be an absolute path')
  if (typeof b.prompt !== 'string' || b.prompt.length === 0 || b.prompt.includes('\0') || Buffer.byteLength(b.prompt, 'utf8') > MAX_PROMPT_BYTES) {
    throw new BadRequest(400, `prompt: a non-empty string of at most ${MAX_PROMPT_BYTES} bytes, without NUL`)
  }
  if (b.mode !== 'normal' && b.mode !== 'canary') throw new BadRequest(400, 'mode: must be "normal" or "canary"')
  const approvalId = b.canary_approval_id
  if (approvalId !== undefined && (typeof approvalId !== 'string' || !APPROVAL_ID_RE.test(approvalId))) throw new BadRequest(400, 'canary_approval_id: not an approval id')
  if (b.mode === 'normal' && approvalId !== undefined) throw new BadRequest(400, 'canary_approval_id: only with mode "canary"')
  if (b.mode === 'canary' && approvalId === undefined) return reply(res, { reason: 'canary_approval_missing' }, 409)
  const canaryId = b.mode === 'canary' ? (approvalId as string) : undefined

  const req: HeadlessRunRequest = { node_id: b.node_id, model: b.model, effort: b.effort, budget_usd: b.budget_usd, cwd: b.cwd, prompt: b.prompt, mode: b.mode }
  const runCtx: StartContext = { caller: caller as string, canaryApprovalId: canaryId }
  const pre = runner.precheck(req, runCtx)
  if (!pre.ok) return reply(res, { reason: pre.reason, ...(pre.detail ? { detail: pre.detail } : {}) }, runRefusalStatus(pre.reason))
  // The gate's own word comes again, atomically, with the reservation; asked
  // here so a canary approval is not spent on a gate that cannot run it.
  const st = gate.status()
  if (st.state !== 'OPEN') return reply(res, { reason: 'gate_closed', detail: st.reason }, 409)
  // K-01 (N7B1): canary_in_progress while its run goes on, canary_window_open until its after-reading.
  const canaryBlock = gate.canaryBlock()
  if (canaryBlock !== null) return reply(res, { reason: canaryBlock }, 409)
  // BE-4b: a canary only alone, so its cost is the only one between its readings (reserve() checks it again).
  if (canaryId !== undefined && gate.openReservationCount() > 0) return reply(res, { reason: 'reservations_open' }, 409)

  let startCtx: StartContext = runCtx
  if (canaryId !== undefined) {
    const proc = rt.calibrations
    if (!proc) return reply(res, { reason: 'canary_unavailable' }, 409)
    const hash = runner.configHash()
    if (hash === null) return reply(res, { reason: 'config_invalid' }, 409)
    // The approval is consumed for this run id; the runner gets its hash for this run only.
    const runId = runner.allocateRunId()
    const c = proc.consumeCanaryApproval(canaryId, hash, {
      model: req.model, budget_micro: budget, runId, node: req.node_id, cwd: req.cwd,
      prompt_sha256: createHash('sha256').update(req.prompt, 'utf8').digest('hex'),
    })
    if (!c.ok) return reply(res, { reason: `canary_${c.reason}` }, 409)
    startCtx = { ...runCtx, runId }
  }
  const r = runner.start(req, startCtx)
  if (!r.ok) {
    // After a consume the approval is spent: the next reading marks the canary undecidable (N2c).
    if (canaryId !== undefined) logger.warn({ reason: r.reason }, 'credit gate: a consumed canary approval did not start its run')
    return reply(res, { reason: r.reason, ...(r.detail ? { detail: r.detail } : {}), ...(canaryId !== undefined ? { approval_spent: true } : {}) }, runRefusalStatus(r.reason))
  }
  return reply(res, { run_id: r.run_id, mode: req.mode, status: 'running' }, 202)
}

export async function tryHandleCreditGate(ctx: RouteContext): Promise<boolean> {
  const { path, method, res } = ctx
  if (path !== PREFIX && !path.startsWith(`${PREFIX}/`)) return false
  const rt = getCreditGateRuntime()
  const mode = rt.mode.mode
  const gate = rt.gate

  try {
    if (path === `${PREFIX}/status`) {
      if (method !== 'GET') {
        methodNotAllowed(res, method, ['GET'])
        return true
      }
      // The delivery state (notify.failed), the auto-rejected approvals and the key reads: N5.
      json(res, { ...(gate ? gate.status() : inactiveStatus(rt)), ...auditStatus(rt.db, Date.now()), canary: canaryView(rt), grant_model: grantModelView(rt) })
      return true
    }

    if (path === `${PREFIX}/reservations`) {
      if (method !== 'POST') {
        methodNotAllowed(res, method, ['POST'])
        return true
      }
      if (mode !== 'enforce') return reply(res, { enforced: false })
      const b = await readObject(ctx, ['kind', 'model', 'input_tokens_total', 'max_output_tokens_total', 'request_count', 'caller'])
      // Over HTTP only the batch client reserves; headless runs reserve inside the dashboard (N4b).
      if (b.kind !== 'batch') throw new BadRequest(400, 'kind: must be "batch"')
      if (typeof b.model !== 'string' || !MODEL_RE.test(b.model)) throw new BadRequest(400, 'model: not a model id')
      if (!intIn(b.input_tokens_total, 0, MAX_TOKENS_TOTAL)) throw new BadRequest(400, 'input_tokens_total: must be a non-negative integer')
      if (!intIn(b.max_output_tokens_total, 0, MAX_TOKENS_TOTAL)) throw new BadRequest(400, 'max_output_tokens_total: must be a non-negative integer')
      if (!intIn(b.request_count, 1, MAX_REQUESTS)) throw new BadRequest(400, `request_count: must be an integer 1..${MAX_REQUESTS}`)
      if (typeof b.caller !== 'string' || !CALLER_RE.test(b.caller)) throw new BadRequest(400, 'caller: not allowed')
      if (!gate) return reply(res, { enforced: true, reason: 'gate_not_running' }, 409)
      const r = gate.reserve({
        kind: 'batch',
        model: b.model,
        input_tokens_total: b.input_tokens_total,
        max_output_tokens_total: b.max_output_tokens_total,
        request_count: b.request_count,
        caller: b.caller,
      })
      if (!r.enforced) return reply(res, { enforced: false })
      if (r.ok) return reply(res, { enforced: true, reservation_id: r.reservation_id, amount_usd: formatUsd(r.amount_micro) })
      return reply(res, { enforced: true, reason: r.reason, ...(r.detail ? { detail: r.detail } : {}) }, 409)
    }

    const op = RES_OP_RE.exec(path)
    if (op) {
      if (method !== 'POST') {
        methodNotAllowed(res, method, ['POST'])
        return true
      }
      if (mode !== 'enforce') return reply(res, { enforced: false })
      const id = op[1]
      const action = op[2]
      if (action === 'bind') {
        const b = await readObject(ctx, ['batch_id', 'expected_requests'])
        if (typeof b.batch_id !== 'string' || !BATCH_ID_RE.test(b.batch_id)) throw new BadRequest(400, 'batch_id: not a batch id')
        if (!intIn(b.expected_requests, 1, MAX_REQUESTS)) throw new BadRequest(400, `expected_requests: must be an integer 1..${MAX_REQUESTS}`)
        if (!gate) return reply(res, { enforced: true, reason: 'gate_not_running' }, 409)
        if (!ID_RE.test(id)) return reply(res, { enforced: true, ok: false, reason: 'not_found' }, 404)
        return opAnswer(ctx, gate.bind(id, b.batch_id, b.expected_requests))
      }
      if (action === 'release') {
        const b = await readObject(ctx, ['reason'])
        if (b.reason !== 'rejected_4xx' && b.reason !== 'unknown_outcome') {
          throw new BadRequest(400, 'reason: must be "rejected_4xx" or "unknown_outcome"')
        }
        if (!gate) return reply(res, { enforced: true, reason: 'gate_not_running' }, 409)
        if (!ID_RE.test(id)) return reply(res, { enforced: true, ok: false, reason: 'not_found' }, 404)
        return opAnswer(ctx, gate.release(id, b.reason))
      }
      await readObject(ctx, [], [], true)
      if (!gate) return reply(res, { enforced: true, reason: 'gate_not_running' }, 409)
      if (!ID_RE.test(id)) return reply(res, { enforced: true, ok: false, reason: 'not_found' }, 404)
      return opAnswer(ctx, gate.complete(id))
    }

    if (path === `${PREFIX}/signals`) {
      if (method !== 'POST') {
        methodNotAllowed(res, method, ['POST'])
        return true
      }
      if (mode === 'off') return reply(res, { enforced: false })
      const b = await readObject(ctx, ['kind', 'source'], ['detail'])
      if (typeof b.kind !== 'string' || !(SIGNAL_KINDS as readonly string[]).includes(b.kind)) {
        throw new BadRequest(400, `kind: must be one of ${SIGNAL_KINDS.join(', ')}`)
      }
      if (typeof b.source !== 'string' || !SOURCE_RE.test(b.source)) throw new BadRequest(400, 'source: not allowed')
      if (b.detail !== undefined && b.detail !== null && (typeof b.detail !== 'string' || b.detail.length > 2000)) {
        throw new BadRequest(400, 'detail: must be a string of at most 2000 characters')
      }
      if (!gate) return reply(res, { enforced: mode === 'enforce', reason: 'gate_not_running' }, 409)
      const r = gate.signal(b.kind as SignalKind, b.source, typeof b.detail === 'string' ? b.detail : null)
      return reply(res, { enforced: r.enforced, state: r.state })
    }

    if (path === `${PREFIX}/runs`) {
      if (method !== 'POST') {
        methodNotAllowed(res, method, ['POST'])
        return true
      }
      const why = runsUnavailable(mode, gate)
      if (why !== null) return reply(res, { reason: why }, 409)
      return await startRun(ctx, rt, gate as CreditGate, getHeadlessRunner() as HeadlessRunner)
    }

    const run = RUN_PATH_RE.exec(path)
    if (run || path.startsWith(`${PREFIX}/runs/`)) {
      const cancel = run?.[2] === '/cancel'
      if (method !== (cancel ? 'POST' : 'GET')) {
        methodNotAllowed(res, method, [cancel ? 'POST' : 'GET'])
        return true
      }
      const why = runsUnavailable(mode, gate)
      if (why !== null) return reply(res, { reason: why }, 409)
      const runner = getHeadlessRunner() as HeadlessRunner
      if (cancel) await readObject(ctx, [], [], true)
      const caller = callerOf(ctx)
      const id = run?.[1] ?? ''
      const rec = RUN_ID_RE.test(id) ? runner.runRecord(id) : null
      // B7: its own run, its caller may always see and stop -- also when the
      // config went invalid or dropped the caller meanwhile (checkCaller reads
      // the config), so a live run is never left without anyone to cancel it.
      // Anyone else gets exactly what an unknown id gets: the run does not show.
      if (rec === null || caller === null || rec.caller !== caller) {
        const callerRefusal = runner.checkCaller(caller)
        if (callerRefusal !== null) return reply(res, { reason: callerRefusal }, 409)
        // BE-4b P4: a run exists only for the caller who started it.
        return reply(res, { reason: 'not_found' }, 404)
      }
      if (!cancel) return reply(res, runView(rec))
      if (runner.cancel(id)) return reply(res, { run_id: id, cancelling: true }, 202)
      return reply(res, { reason: 'not_running', status: rec.status }, 409)
    }

    json(res, { error: 'Not found' }, 404)
    return true
  } catch (err) {
    if (err instanceof BadRequest) {
      json(res, { error: err.message }, err.status)
      return true
    }
    throw err
  }
}

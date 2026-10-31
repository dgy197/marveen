#!/usr/bin/env node
// PreToolUse hook (Bash): SHADOW mode of the Bash egress gate (card 59d87635, owner GO for shadow only).
//
// It runs the SAME classification as the enforcing gate (scripts/hooks/bash-egress-parser.mjs:
// classify, measureOnly, the vendor-host lists are imported, not copied) and records what the gate
// WOULD have decided. It never denies: it always exits 0 and prints nothing, whatever the classifier
// says, and also when the classifier throws, hangs into the hook timeout, or the input is garbage.
// There is deliberately no switch (argument, env variable, file) that turns it into enforce: the
// enforcing entry point is bash-egress-parser.mjs, and moving the main agent over is a separate,
// explicit GO after the shadow log has been read (docs/egress-shadow-main-agent.md).
//
// LOG: one JSONL line per Bash call in store/egress-shadow.jsonl (0600). Fields: ts, cmd_sha256,
// decision ("allow" | "deny-would-be"), reason (code), agent. NEVER the command text, a URL, a host or
// any token: the parser's hosts list and error messages are not copied (they can quote the command).
// The file is capped: at ROTATE_AT bytes it is renamed to egress-shadow.jsonl.1 (replacing the older
// one), so the pair stays under 5 MB. Any log failure is swallowed: it never blocks the call.
//
// --main-scope behaves as in the enforcing hook: only a session on a config dir of its own is judged.

import { readFileSync, openSync, writeSync, closeSync, fstatSync, renameSync, mkdirSync, realpathSync, constants } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createHash } from 'node:crypto'
import { classify, measureOnly, loadMeasureHosts, loadVendorHosts, loadVendorDomains, setHookCwd, mainScopeAppliesTo } from './bash-egress-parser.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
// The env override exists for tests only; it moves the log, it cannot change a decision.
export const SHADOW_LOG = process.env.EGRESS_SHADOW_LOG || join(ROOT, 'store', 'egress-shadow.jsonl')
// File + its ".1" rotation stay under 5 MB (2 x 2 MiB = 4.2 MB, plus one line of slack).
export const ROTATE_AT = 2 * 1024 * 1024

const sha256 = (s) => createHash('sha256').update(String(s)).digest('hex')

// Agent id: a sub-agent's payload carries agent_type; else the install's agent-id env; else null.
// Only a short plain identifier is kept, so a hostile value cannot smuggle text into the log.
export function agentIdOf(payload, env = process.env) {
  for (const v of [payload?.agent_type, env.MARVEEN_AGENT_ID, env.MAIN_AGENT_ID]) {
    if (typeof v === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(v)) return v
  }
  return null
}

// The pure record for one payload. `deps` lets a test make the classifier throw.
export function shadowRecord(payload, deps = {}) {
  const cls = deps.classify ?? classify
  const measure = deps.measureOnly ?? measureOnly
  const base = { ts: new Date().toISOString(), cmd_sha256: null, decision: 'allow', reason: null, agent: agentIdOf(payload) }
  const command = payload?.tool_input?.command
  base.cmd_sha256 = sha256(typeof command === 'string' ? command : '')
  try {
    setHookCwd(payload?.cwd)
    if (measure(command, loadMeasureHosts())) return { ...base, reason: 'measure-only' }
    const r = cls(command, 0, loadVendorHosts(), loadVendorDomains())
    if (r?.deny) return { ...base, decision: 'deny-would-be', reason: typeof r.reason === 'string' ? r.reason : 'unknown' }
    return { ...base, reason: 'clean' }
  } catch (e) {
    // The error NAME only: a message can quote the command.
    return { ...base, reason: `shadow-error:${typeof e?.name === 'string' ? e.name.slice(0, 40) : 'unknown'}` }
  }
}

export function appendShadowLog(record, path = SHADOW_LOG) {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    // O_NOFOLLOW: a planted symlink at the log path is refused (the write is then simply lost).
    const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600)
    try {
      if (fstatSync(fd).size >= ROTATE_AT) {
        try { renameSync(path, `${path}.1`) } catch { /* keep appending to the big file rather than lose the line */ }
      }
      writeSync(fd, JSON.stringify(record) + '\n')
    } finally { closeSync(fd) }
    return true
  } catch {
    return false
  }
}

// The whole hook body. Returns nothing the caller could turn into a deny; always safe to exit 0 after.
export function runShadow(rawInput, opts = {}) {
  try {
    let payload
    try { payload = JSON.parse(rawInput) } catch {
      appendShadowLog({ ts: new Date().toISOString(), cmd_sha256: null, decision: 'allow', reason: 'bad-input', agent: agentIdOf(null) }, opts.logPath)
      return
    }
    if (payload?.tool_name !== 'Bash') return
    appendShadowLog(shadowRecord(payload, opts.deps), opts.logPath)
  } catch { /* nothing here may block the call */ }
}

function isInvokedDirectly() {
  try { return realpathSync(fileURLToPath(import.meta.url)) === (process.argv[1] ? realpathSync(process.argv[1]) : '') } catch { return false }
}

if (isInvokedDirectly()) {
  process.on('uncaughtException', () => process.exit(0))
  process.on('unhandledRejection', () => process.exit(0))
  try {
    if (!(process.argv.includes('--main-scope') && !mainScopeAppliesTo())) {
      let raw = ''
      try { raw = readFileSync(0, 'utf-8') } catch { /* empty stdin: logged as bad-input below */ }
      runShadow(raw)
    }
  } catch { /* swallowed */ }
  process.exit(0)
}

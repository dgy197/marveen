#!/usr/bin/env node
// Measurement harness for the Bash egress gate (card f0e9aee4, node N0a).
//
// Reads corpus files (JSON lines: {id, class, family?, group?, cmd, expect}) and runs ONLY
// classify() from the parser on each cmd. It never executes a corpus command and opens no socket:
// the commands are strings. Run it under a loopback-only socket guard (see README in the report).
//
//   node measure.mjs [corpus.jsonl ...] [--parser <path.mjs>] [--compare <path.mjs>]
//                    [--quiet] [--json <out.json>] [--show-cmd]
//
// Default corpus: everyday.jsonl + legit-edge.jsonl next to this file. Default parser: the repo's
// scripts/hooks/bash-egress-parser.mjs. --compare runs a second parser (e.g. the base copy) over the
// same commands and counts every difference in (deny, reason, hosts): the A5 pairwise check.
//
// Per command it prints: id, class, deny, reason, hosts, warm time (ms). Summary: per class count,
// deny count, unparseable count, expectation mismatches, and p50/p95/max of the warm and the cold
// (first, uncached) classify() time. Commands are printed only with --show-cmd (they can be long).
// Exit code 1 when any class E command is denied (E must be 0), else 0.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import net from 'node:net'

const HERE = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const opt = (name) => { const i = args.indexOf(name); if (i === -1) return null; const v = args[i + 1]; args.splice(i, 2); return v }
const flag = (name) => { const i = args.indexOf(name); if (i === -1) return false; args.splice(i, 1); return true }
const parserPath = resolve(opt('--parser') ?? join(HERE, '..', '..', '..', '..', 'scripts', 'hooks', 'bash-egress-parser.mjs'))
const comparePath = opt('--compare')
const jsonOut = opt('--json')
const quiet = flag('--quiet')
const showCmd = flag('--show-cmd')
const files = args.length ? args.map((f) => resolve(f)) : [join(HERE, 'everyday.jsonl'), join(HERE, 'legit-edge.jsonl')]

const load = async (p) => (await import(pathToFileURL(resolve(p)).href)).classify
const classify = await load(parserPath)
const classify2 = comparePath ? await load(comparePath) : null

const rows = []
for (const f of files) {
  if (!existsSync(f)) { console.error(`missing corpus file: ${f}`); process.exit(2) }
  for (const [n, line] of readFileSync(f, 'utf-8').split('\n').entries()) {
    if (!line.trim()) continue
    try { rows.push({ ...JSON.parse(line), file: f }) } catch { console.error(`${f}:${n + 1}: not JSON`); process.exit(2) }
  }
}
const ids = new Set()
for (const r of rows) {
  if (typeof r.cmd !== 'string' || !r.id || !r.class) { console.error(`bad row: ${JSON.stringify(r.id)}`); process.exit(2) }
  if (ids.has(r.id)) { console.error(`duplicate id: ${r.id}`); process.exit(2) }
  ids.add(r.id)
}

const ms = (a, b) => Number(b - a) / 1e6
// Pass 1 (cold): the first call of each command, no warm-up, as a fresh hook process would see it
// (a real hook is a new node process per call, so this is the closer number). Pass 2 (warm).
const results = []
for (const r of rows) {
  const t0 = process.hrtime.bigint()
  let res, err = null
  try { res = classify(r.cmd) } catch (e) { err = String(e?.message ?? e); res = { deny: false, reason: 'EXCEPTION', hosts: [] } }
  const cold = ms(t0, process.hrtime.bigint())
  results.push({ r, res, err, cold })
}
for (const o of results) {
  const t0 = process.hrtime.bigint()
  try { classify(o.r.cmd) } catch { /* already recorded */ }
  o.warm = ms(t0, process.hrtime.bigint())
}
let diffs = []
if (classify2) {
  for (const o of results) {
    let b
    try { b = classify2(o.r.cmd) } catch (e) { b = { deny: null, reason: 'EXCEPTION', hosts: [] } }
    const a = o.res
    if (a.deny !== b.deny || a.reason !== b.reason || JSON.stringify(a.hosts) !== JSON.stringify(b.hosts)) diffs.push({ id: o.r.id, a, b })
  }
}

const pct = (arr, p) => { if (!arr.length) return 0; const s = [...arr].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)] }
const fmt = (n) => n.toFixed(3)
if (!quiet) {
  for (const o of results) {
    const tag = o.r.family ?? o.r.group ?? '-'
    console.log([o.r.id, o.r.class, tag, o.res.deny ? 'DENY' : 'allow', o.res.reason ?? '-', o.res.hosts.join(',') || '-', fmt(o.warm), o.err ? `ERR:${o.err}` : '', showCmd ? JSON.stringify(o.r.cmd) : ''].join('\t').trimEnd())
  }
}

const classes = [...new Set(results.map((o) => o.r.class))].sort()
const summary = { parser: parserPath, files, total: results.length, classes: {}, all: {} }
const stat = (list) => ({
  n: list.length,
  deny: list.filter((o) => o.res.deny).length,
  unparseable: list.filter((o) => o.res.reason === 'unparseable').length,
  exceptions: list.filter((o) => o.err).length,
  expect_mismatch: list.filter((o) => (o.r.expect === 'allow' && o.res.deny) || (o.r.expect === 'deny' && !o.res.deny)).length,
  warm_ms: { p50: pct(list.map((o) => o.warm), 0.5), p95: pct(list.map((o) => o.warm), 0.95), max: pct(list.map((o) => o.warm), 1) },
  cold_ms: { p50: pct(list.map((o) => o.cold), 0.5), p95: pct(list.map((o) => o.cold), 0.95), max: pct(list.map((o) => o.cold), 1) },
})
for (const c of classes) summary.classes[c] = stat(results.filter((o) => o.r.class === c))
summary.all = stat(results)
summary.denied = results.filter((o) => o.res.deny).map((o) => ({ id: o.r.id, class: o.r.class, tag: o.r.family ?? o.r.group ?? null, reason: o.res.reason, hosts: o.res.hosts }))
if (classify2) summary.compare = { parser: resolve(comparePath), differences: diffs.length, ids: diffs.map((d) => d.id) }

// Loopback guard evidence: the guard from card 3d84bec8 marks net.Socket.prototype.connect.
const guardActive = Boolean(net.Socket.prototype.connect[Symbol.for('marveen.3d84bec8.loopbackGuard')])
summary.loopback_guard_active = guardActive

console.log('--- summary')
for (const c of classes) {
  const s = summary.classes[c]
  console.log(`class ${c}: n=${s.n} deny=${s.deny} unparseable=${s.unparseable} exceptions=${s.exceptions} expect_mismatch=${s.expect_mismatch} warm p50/p95/max=${fmt(s.warm_ms.p50)}/${fmt(s.warm_ms.p95)}/${fmt(s.warm_ms.max)} ms cold p50/p95/max=${fmt(s.cold_ms.p50)}/${fmt(s.cold_ms.p95)}/${fmt(s.cold_ms.max)} ms`)
}
const a = summary.all
console.log(`all: n=${a.n} deny=${a.deny} warm p50/p95/max=${fmt(a.warm_ms.p50)}/${fmt(a.warm_ms.p95)}/${fmt(a.warm_ms.max)} ms cold p50/p95/max=${fmt(a.cold_ms.p50)}/${fmt(a.cold_ms.p95)}/${fmt(a.cold_ms.max)} ms`)
for (const d of summary.denied) console.log(`denied: ${d.id} class=${d.class} tag=${d.tag} reason=${d.reason} hosts=${d.hosts.join(',') || '-'}`)
if (classify2) console.log(`compare: ${diffs.length} difference(s) vs ${resolve(comparePath)}${diffs.length ? ': ' + diffs.map((d) => d.id).join(',') : ''}`)
console.log(`loopback guard active: ${guardActive}`)
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n')
process.exit(summary.classes.E?.deny ? 1 : 0)

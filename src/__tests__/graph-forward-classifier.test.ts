import { describe, it, expect, afterAll } from 'vitest'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, isSendInvocation } from '../../scripts/email-send-gate.mjs'

// graph-forward (Brainy 2958, N1): the gates learn the Graph CLI's forward BEFORE
// the CLI has it, so no tree state can carry a forward the gates do not see.
// Before this change `graph-mail.ts forward ...` read as "not a send" in both
// classifier twins (T2), and so did a CLI send behind a shlex-unparseable ANSI-C
// quote in the python twin (T3): the main agent's approval gate and copy gate
// let both through, and the sub-agent hard-gate let the forward through.
//
// What this file pins (the per-command verdicts live in send-invocation-cases.json,
// run by send-invocation-conformance.test.ts):
//   1. every forward command of the shared forward vectors (graph-forward-cases.json,
//      gate_commands: the B1-B5 rule cases, accepted and refused alike) is a send in
//      BOTH twins -- a forward the classifier misses would never reach the forward
//      rules of the approval gate at all;
//   2. the hooks themselves, run the way .claude/settings.json runs them, refuse a
//      forward with no approval: the approval gate at level 1 and 2, the copy gate on
//      a comment it must not let out, the sub-agent gate always. These hold with and
//      without the gate's forward extraction (N2), so they stay true after it lands;
//   3. the T3 send is refused by the approval gate (it used to pass at level 2);
//   4. the reads stay reads end to end: a `list` passes all three hooks.

const ROOT = join(__dirname, '..', '..')
const HOOKS = join(ROOT, 'scripts', 'hooks')
const COPY_GATE = join(HOOKS, 'outgoing-copy-gate.py')
const APPROVAL_GATE = join(HOOKS, 'email-approval-gate.py')
const SEND_GATE = join(ROOT, 'scripts', 'email-send-gate.mjs')
const VECTORS = JSON.parse(readFileSync(join(HOOKS, 'graph-forward-cases.json'), 'utf-8')) as {
  gate_commands: Array<{ name: string; cmd: string; expect: string; rule: string }>
}
const GATE_CMDS = VECTORS.gate_commands
const EM_DASH = String.fromCharCode(0x2014)
const FWD = (comment: string) =>
  `npx tsx scripts/graph-mail.ts forward --id AAMkAGFmZXN0MDEyMzQ1Njc4OQ== --to kovacs@fireeng.hu ` +
  `--comment '${comment}' --orig-subject 'Targy'`
const T3_SEND = "echo $'it\\'s'; npx tsx scripts/graph-mail.ts send --to a@b.hu --subject X --body Y"
const LIST = 'npx tsx scripts/graph-mail.ts list --top 3'

function pythonIsSend(cmds: string[]): boolean[] {
  const out = execFileSync('python3', ['-c', `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("gate", ${JSON.stringify(COPY_GATE)})
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
print(json.dumps([g.is_send_invocation(c) for c in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(cmds) })
  return JSON.parse(out.trim())
}

const dirs: string[] = []
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

// A hermetic store per call: the approval gate reads its level, standing list and
// approvals DB from EMAIL_APPROVAL_GATE_STORE, the copy gate its rules (and log) from
// OUTGOING_COPY_GATE_RULES. Nothing here can reach the live store.
function store(level: number | null): string {
  const d = realpathSync(mkdtempSync(join(tmpdir(), 'gf-n1-')))
  dirs.push(d)
  if (level !== null) {
    writeFileSync(join(d, 'autonomy-config.json'),
      JSON.stringify({ categories: [{ key: 'email_send', level, maxLevel: 2 }] }))
  }
  return d
}

function runPyHook(hook: string, command: string, level: number | null) {
  const d = store(level)
  const r = spawnSync('python3', [hook], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
    env: { ...process.env, EMAIL_APPROVAL_GATE_STORE: d, OUTGOING_COPY_GATE_RULES: join(d, 'rules.json') },
    encoding: 'utf-8',
    timeout: 30_000,
  })
  return { status: r.status, stderr: r.stderr ?? '' }
}

function runSendGate(command: string) {
  const r = spawnSync('node', [SEND_GATE], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
    encoding: 'utf-8',
    timeout: 30_000,
  })
  const out = (r.stdout ?? '').trim()
  return { status: r.status, decision: out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : null }
}

describe('graph-forward N1: every shared forward vector is a send in both twins', () => {
  const py = pythonIsSend(GATE_CMDS.map((c) => c.cmd))

  it('the vector list is the full B1-B5 set, accepted and refused cases alike (guards the test itself)', () => {
    expect(GATE_CMDS.length).toBeGreaterThanOrEqual(70)
    expect(GATE_CMDS.some((c) => c.expect === 'rules-ok')).toBe(true)
    expect(GATE_CMDS.some((c) => c.expect === 'deny')).toBe(true)
  })

  GATE_CMDS.forEach((c, i) => {
    it(`${c.rule} ${c.name}`, () => {
      expect(isSendInvocation(c.cmd), `JS verdict for: ${c.cmd}`).toBe(true)
      expect(gateDecision('Bash', { command: c.cmd }, () => true).deny, `JS gate for: ${c.cmd}`).toBe(true)
      expect(py[i], `python verdict for: ${c.cmd}`).toBe(true)
    })
  })
})

// Review round 1 (GS1, GR2): a verb the shell assembles, and a plain send that only
// quotes the forward. The per-command verdicts of the approval gate are pinned in
// scripts/__tests__/graph-forward-gate.test.py; what must hold here is that the
// SUB-AGENT gate and both classifier twins still call every one of them a send --
// the fail-closed change in the extractor must not have weakened them.
const GS1_VECTORS = JSON.parse(readFileSync(join(HOOKS, 'graph-forward-gs1-cases.json'), 'utf-8')) as {
  gs1: Array<{ name: string; cmd: string }>
  gr2: Array<{ name: string; cmd: string }>
}

describe('graph-forward GS1/GR2: both twins and the sub-agent gate read them as sends', () => {
  const all = [...GS1_VECTORS.gs1.map((c) => ({ ...c, tag: 'GS1' })), ...GS1_VECTORS.gr2.map((c) => ({ ...c, tag: 'GR2' }))]
  const py = pythonIsSend(all.map((c) => c.cmd))

  it('the vector lists are whole (guards the test itself)', () => {
    expect(GS1_VECTORS.gs1.length).toBeGreaterThanOrEqual(20)
    expect(GS1_VECTORS.gr2.length).toBeGreaterThanOrEqual(4)
  })

  all.forEach((c, i) => {
    it(`${c.tag} ${c.name}`, () => {
      expect(isSendInvocation(c.cmd), `JS verdict for: ${c.cmd}`).toBe(true)
      expect(gateDecision('Bash', { command: c.cmd }, () => true).deny, `JS gate for: ${c.cmd}`).toBe(true)
      expect(py[i], `python verdict for: ${c.cmd}`).toBe(true)
    })
  })

  it('sub-agent gate (the hook process): a brace-assembled forward is denied', () => {
    expect(runSendGate(GS1_VECTORS.gs1[0].cmd)).toEqual({ status: 0, decision: 'deny' })
  })
})

describe('graph-forward N1: the hooks refuse a forward that has no approval', () => {
  it('approval gate, level 1: refused', () => {
    const r = runPyHook(APPROVAL_GATE, FWD('Szia Andi! Kérlek, nézd meg.'), 1)
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('EMAIL JOVAHAGYASI KAPU: TILTVA')
  })

  it('approval gate, level 2, no approval and no standing recipient: refused', () => {
    const r = runPyHook(APPROVAL_GATE, FWD('Szia Andi! Kérlek, nézd meg.'), 2)
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('EMAIL JOVAHAGYASI KAPU: TILTVA')
  })

  it('approval gate, missing config (defaults to level 2): refused', () => {
    const r = runPyHook(APPROVAL_GATE, FWD('Szia Andi! Kérlek, nézd meg.'), null)
    expect(r.status).toBe(2)
  })

  it('copy gate: a forward whose comment carries an em dash is blocked', () => {
    const r = runPyHook(COPY_GATE, FWD(`Szia Andi! Kérlek ${EM_DASH} nézd meg.`), 2)
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('KIMENO-SZOVEG KAPU: TILTVA')
  })

  it('sub-agent gate (the hook process): denied', () => {
    expect(runSendGate(FWD('Szia Andi! Kérlek, nézd meg.'))).toEqual({ status: 0, decision: 'deny' })
  })

  it('T3: the ANSI-C-prefixed CLI send is refused by the approval gate at level 2 (it used to pass)', () => {
    const r = runPyHook(APPROVAL_GATE, T3_SEND, 2)
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('EMAIL JOVAHAGYASI KAPU: TILTVA')
  })
})

// r3 (Brainy 3092, 3094): the graph-mail whitelist. The per-vector verdicts of BOTH real gates
// (levels 1, 2 with a live standing recipient and 3; the copy gate) are pinned in
// scripts/__tests__/graph-forward-gate.test.py. What must hold here: the Python classifier gives
// every shared vector its kind (one process), the two golden bypasses of round 2 are refused by the
// hooks as the settings run them, a read is let through, and the sub-agent gate (unchanged, JS)
// still allows what it allowed and still refuses what it refused.
const GRAMMAR = JSON.parse(readFileSync(join(HOOKS, 'graph-mail-grammar-cases.json'), 'utf-8')) as {
  cases: Array<{ name: string; cmd: string; expect: string; rule: string; gate?: string }>
}
const GM_MARK = 'Graph-mail kapu (graph-mail parancs)'

function grammarRoot(): string {
  const d = realpathSync(mkdtempSync(join(tmpdir(), 'gf-r3-')))
  dirs.push(d)
  for (const name of ['a.txt', 'b.txt']) writeFileSync(join(d, name), 'Szia!', { mode: 0o600 })
  return d
}

function pythonKinds(cmds: string[], outbox: string): string[] {
  const out = execFileSync('python3', ['-I', '-c', `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("ee", ${JSON.stringify(join(HOOKS, 'email_extract.py'))})
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps([m.classify_graph_mail(c)[0] for c in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(cmds), env: { ...process.env, GRAPH_MAIL_OUTBOX_DIR: outbox } })
  return JSON.parse(out.trim())
}

describe('graph-forward r3: the graph-mail whitelist', () => {
  const outbox = grammarRoot()
  const cmds = GRAMMAR.cases.map((c) => c.cmd.split('{ROOT}').join(outbox).split('{REPO}').join(ROOT))
  const kinds = pythonKinds(cmds, outbox)

  it('the vector list is whole (guards the test itself)', () => {
    expect(GRAMMAR.cases.length).toBeGreaterThanOrEqual(190)
    for (const k of ['deny', 'read', 'send', 'forward', 'none']) {
      expect(GRAMMAR.cases.some((c) => c.expect === k), k).toBe(true)
    }
  })

  GRAMMAR.cases.forEach((c, i) => {
    it(`${c.expect} ${c.rule} ${c.name}`, () => {
      expect(kinds[i], `kind of: ${cmds[i]}`).toBe(c.expect)
    })
  })

  const B1 = GRAMMAR.cases.find((c) => c.rule === 'B1')!.cmd
  const X1 = GRAMMAR.cases.filter((c) => c.rule === 'X1').map((c) => c.cmd)

  for (const [label, cmd] of [['B1', B1], ['X1 plain', X1[0]], ['X1 with a --body decoy', X1[1]]] as const) {
    for (const level of [1, 2, 3]) {
      it(`approval gate, level ${level}: ${label} is refused on the grammar, not on the level`, () => {
        const r = runPyHook(APPROVAL_GATE, cmd, level)
        expect(r.status).toBe(2)
        expect(r.stderr).toContain(GM_MARK)
      })
    }
    it(`copy gate: ${label} is blocked`, () => {
      const r = runPyHook(COPY_GATE, cmd, 2)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('KIMENO-SZOVEG KAPU: TILTVA')
    })
  }

  it('a read-only head is let through by both hooks, at level 1 too', () => {
    const cmd = 'grep -r graph-mail scripts'
    expect(runPyHook(APPROVAL_GATE, cmd, 1).status).toBe(0)
    expect(runPyHook(COPY_GATE, cmd, 2).status).toBe(0)
  })

  it('sed, git and a chained grep are refused by both hooks', () => {
    for (const cmd of ['sed -n 1p scripts/graph-mail.ts', 'git log -- scripts/graph-mail.ts',
      'grep graph-mail x; npx tsx scripts/graph-mail.ts send --to a@fireeng.hu --subject s --body b']) {
      expect(runPyHook(APPROVAL_GATE, cmd, 3).status, cmd).toBe(2)
      expect(runPyHook(COPY_GATE, cmd, 2).status, cmd).toBe(2)
    }
  })

  it('the sub-agent gate (unchanged JS twin) still refuses a send and a forward and allows a read', () => {
    expect(runSendGate('npx tsx scripts/graph-mail.ts send --to a@fireeng.hu --subject Teszt --body Szia'))
      .toEqual({ status: 0, decision: 'deny' })
    expect(runSendGate(FWD('Szia Andi! Kérlek, nézd meg.'))).toEqual({ status: 0, decision: 'deny' })
    expect(runSendGate('grep -r graph-mail scripts')).toEqual({ status: 0, decision: null })
  })
})

describe('graph-forward N1: a list stays a read through every hook', () => {
  it('approval gate at level 1 lets it through', () => {
    expect(runPyHook(APPROVAL_GATE, LIST, 1).status).toBe(0)
  })

  it('copy gate lets it through', () => {
    expect(runPyHook(COPY_GATE, LIST, 2).status).toBe(0)
  })

  it('sub-agent gate allows it', () => {
    expect(runSendGate(LIST)).toEqual({ status: 0, decision: null })
  })
})

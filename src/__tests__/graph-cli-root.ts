import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// Test fixture for the graph-mail CLI tests (card efa58ad2, cli-send-enforce).
//
// The CLI finds the send authorizer from the checkout it was started from
// (scripts/hooks/email_send_authorize.py next to a copy of scripts/graph-mail.ts),
// and no environment variable can move it. A test that wants to run the CLI
// therefore builds a throwaway "root": a copy of the CLI, `src` and
// `node_modules` symlinked, the two hook files the forward gate probe reads, and
// a helper that is either
//   - 'stub': a Python file that logs the request it got and answers as GS_MODE
//             says (allow by default), or
//   - 'real': a byte copy of the whole scripts/hooks directory (the helper
//             derives store/ from its own realpath, so a copy has its own store/),
//   - 'none': no helper at all.
// This file is a fixture, not a test (no .test suffix).

export type HelperKind = 'stub' | 'real' | 'none'

/** Answers as GS_MODE says; logs every request line to stub-requests.jsonl next to itself. */
export const STUB_HELPER = [
  'import json, os, sys, time',
  'req = sys.stdin.read()',
  "log = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'stub-requests.jsonl')",
  "with open(log, 'a', encoding='utf-8') as fh:",
  "    fh.write(req.strip() + '\\n')",
  // BE2-1 (c3c32903, test setup): the CLI starts the helper with an allowlisted environment, so
  // GS_* no longer arrive through os.environ; setStubEnv() writes them next to the stub instead.
  "try:",
  "    cfg = json.load(open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gs-env.json'), encoding='utf-8'))",
  'except OSError:',
  '    cfg = {}',
  "mode = cfg.get('GS_MODE', 'allow')",
  "reason = cfg.get('GS_REASON', 'none')",
  'def say(obj, code):',
  '    sys.stdout.write(json.dumps(obj) + "\\n")',
  '    sys.stdout.flush()',
  '    sys.exit(code)',
  "allow = {'decision': 'allow', 'reason': cfg.get('GS_ALLOW_REASON', 'approval'), 'approval_id': 'ab12cd', 'anchor': 'a' * 64}",
  "if mode == 'allow':",
  '    say(allow, 0)',
  "if mode == 'refuse':",
  "    say({'decision': 'refuse', 'reason': reason, 'approval_id': None, 'anchor': 'b' * 64, 'detail': 'stub detail'}, 2)",
  "if mode == 'crash':",
  "    raise RuntimeError('stub crash')",
  "if mode == 'hang':",
  '    time.sleep(120)',
  "if mode == 'garbage':",
  "    sys.stdout.write('this is not json\\n')",
  '    sys.exit(0)',
  "if mode == 'empty':",
  '    sys.exit(0)',
  "if mode == 'exit1':",
  '    say(allow, 1)',
  "if mode == 'allow_exit2':",
  '    say(allow, 2)',
  "if mode == 'refuse_exit0':",
  "    say({'decision': 'refuse', 'reason': 'none'}, 0)",
  "if mode == 'two_lines':",
  '    sys.stdout.write(json.dumps(allow) + "\\n" + json.dumps(allow) + "\\n")',
  '    sys.exit(0)',
  "if mode == 'bad_reason':",
  "    say({'decision': 'refuse', 'reason': 'x\\ny'}, 2)",
  "if mode == 'no_decision':",
  "    say({'reason': 'approval'}, 0)",
  'sys.exit(9)',
  '',
].join('\n')

export function makeCliRoot(repo: string, base: string, helper: HelperKind = 'stub'): string {
  const root = realpathSync(mkdtempSync(join(base, 'cli-root-')))
  const hooks = join(root, 'scripts', 'hooks')
  mkdirSync(hooks, { recursive: true })
  mkdirSync(join(root, '.claude'))
  mkdirSync(join(root, 'store'))
  copyFileSync(join(repo, 'scripts', 'graph-mail.ts'), join(root, 'scripts', 'graph-mail.ts'))
  copyFileSync(join(repo, 'package.json'), join(root, 'package.json'))
  symlinkSync(join(repo, 'src'), join(root, 'src'))
  symlinkSync(join(repo, 'node_modules'), join(root, 'node_modules'))
  copyFileSync(join(repo, '.claude', 'settings.json'), join(root, '.claude', 'settings.json'))
  if (helper === 'real') {
    cpSync(join(repo, 'scripts', 'hooks'), hooks, { recursive: true })
    // the copy gate's QA imports scripts/lib (mixed_script.py); without it the QA fails closed
    cpSync(join(repo, 'scripts', 'lib'), join(root, 'scripts', 'lib'), { recursive: true })
  } else {
    for (const f of ['outgoing-copy-gate.py', 'email_extract.py']) {
      copyFileSync(join(repo, 'scripts', 'hooks', f), join(hooks, f))
    }
    if (helper === 'stub') writeFileSync(join(hooks, 'email_send_authorize.py'), STUB_HELPER)
  }
  return root
}

/**
 * Hands the GS_* knobs (GS_MODE, GS_REASON, GS_ALLOW_REASON) to the stub helper of `root`.
 * Only GS_* keys are taken from `vars`; none and no earlier file: nothing is written; none but
 * an earlier file: the file is reset, so a reused root never keeps the last test's mode.
 */
export function setStubEnv(root: string, vars: Record<string, string | undefined> = {}): void {
  const file = join(root, 'scripts', 'hooks', 'gs-env.json')
  const cfg: Record<string, string> = {}
  for (const [k, v] of Object.entries(vars)) if (k.startsWith('GS_') && typeof v === 'string') cfg[k] = v
  if (Object.keys(cfg).length === 0 && !existsSync(file)) return
  writeFileSync(file, JSON.stringify(cfg))
}

export interface ShimTrap {
  /** A fake DEVELOPER_DIR: usr/bin/xcrun and Library/Developer/CommandLineTools/usr/bin/python3 both touch `marker`. */
  developerDir: string
  /** A directory with a python3 shim that touches `marker` and answers "allow"; for the front of PATH. */
  fakeBin: string
  marker: string
  /** DEVELOPER_DIR, SDKROOT and TOOLCHAINS pointing into the fake tree. */
  env: Record<string, string>
}

/**
 * BE2-1 (card c3c32903): what an attacker prefixes to a send. Nothing the product runs may ever
 * start one of these files: `existsSync(trap.marker)` stays false. The python shims also print an
 * "allow" verdict, so a run that used one would show up as an allowed send as well.
 */
export function makeShimTrap(base: string): ShimTrap {
  const dir = realpathSync(mkdtempSync(join(base, 'shim-trap-')))
  const marker = join(dir, 'shim-was-run')
  const allow = '{"decision":"allow","reason":"approval","approval_id":"shim","anchor":null}'
  const shim = `#!/bin/sh\necho "$0" >> '${marker}'\necho '${allow}'\nexit 0\n`
  const developerDir = join(dir, 'developer')
  const clt = join(developerDir, 'Library', 'Developer', 'CommandLineTools', 'usr', 'bin')
  const fakeBin = join(dir, 'fakebin')
  for (const d of [join(developerDir, 'usr', 'bin'), clt, fakeBin]) mkdirSync(d, { recursive: true })
  for (const f of [join(developerDir, 'usr', 'bin', 'xcrun'), join(clt, 'python3'), join(fakeBin, 'python3')]) {
    writeFileSync(f, shim)
    chmodSync(f, 0o755)
  }
  return {
    developerDir,
    fakeBin,
    marker,
    env: { DEVELOPER_DIR: developerDir, SDKROOT: developerDir, TOOLCHAINS: 'com.attacker.toolchain' },
  }
}

/** The requests the stub helper of `root` received, parsed, in order. */
export function stubRequests(root: string): Array<Record<string, any>> {
  const log = join(root, 'scripts', 'hooks', 'stub-requests.jsonl')
  if (!existsSync(log)) return []
  return readFileSync(log, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, any>)
}

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { STUB_HELPER, makeCliRoot } from './graph-cli-root.js'

// scripts/graph-mail.ts `send` and `forward` run the opt-in verified-recipient
// ledger (MAIN_AGENT_RECIPIENT_LEDGER=1 in the install .env) before the token
// request and before the authorizer. Since the v1.45.0 merge (card c3c32903) the
// CLI does NOT call sender_check.check(): the email_send level, the standing list,
// the copy audit and the one-shot approval belong to the authorizer
// (src/graph-send-authorize.ts, tested in graph-send-authorize.test.ts and
// graph-cli-enforce-matrix.test.ts), and sender_check.check() would spend the
// approval a second time. So the upstream cases of this file that exercised the
// level / approval / standing / copy path through sender_check are gone on purpose;
// what stays is the ledger half, the off-by-default rule and the PATH/PYTHONPATH
// hijack cases. Graph is a fetch stub, the authorizer an allow-stub: no
// credential, no network.
const ROOT = join(__dirname, '..', '..')
const TSX = join(ROOT, 'node_modules', '.bin', 'tsx')

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'graph-sender-check-')))
const FAKE_TOKEN = `FAKE-sc-access-token-${'q4w8'.repeat(4)}`
const CREDS = join(BASE, 'fake-mail-creds')
writeFileSync(
  CREDS,
  [
    'TENANT_ID=00000000-0000-4000-8000-000000000001',
    'CLIENT_ID=00000000-0000-4000-8000-000000000002',
    `CLIENT_SECRET=FAKE-sc-client-secret-${'z1x5'.repeat(4)}`,
    'MAILBOX=sc-test-box@example.invalid',
  ].join('\n'),
  { mode: 0o600 },
)
const OUTBOX = join(BASE, 'outbox')
mkdirSync(OUTBOX, { mode: 0o700 })
chmodSync(OUTBOX, 0o700)

const FETCH_STUB = [
  "import { appendFileSync, readFileSync } from 'node:fs'",
  "const scenario = JSON.parse(readFileSync(process.env.SC_SCENARIO, 'utf8'))",
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/sendMail')) kind = 'sendmail'",
  "  else if (method === 'POST' && url.endsWith('/forward')) kind = 'forward'",
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  appendFileSync(process.env.SC_LOG, JSON.stringify({ kind }) + '\\n')",
  '  const reply = scenario[kind]',
  "  if (!reply) throw new Error('fetch stub: unexpected ' + kind + ' call')",
  "  const text = reply.body === undefined ? null : JSON.stringify(reply.body)",
  "  return new Response(text, { status: reply.status ?? 200, headers: { 'content-type': 'application/json' } })",
  '}',
  '',
].join('\n')
const STUB = join(BASE, 'fetch-stub.mjs')
writeFileSync(STUB, FETCH_STUB)

const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const FWD_SUBJ = 'Ajánlatkérés: iroda átalakítás'
const TOKEN_OK = { status: 200, body: { access_token: FAKE_TOKEN, token_type: 'Bearer', expires_in: 3600 } }
const SEND_OK = { token: TOKEN_OK, sendmail: { status: 202 } }
const FWD_OK = { token: TOKEN_OK, message: { status: 200, body: { id: ID, subject: FWD_SUBJ } }, forward: { status: 202 } }

let root = ''
let seq = 0

/** A root with the real hooks (sender_check.py, the gates, the ledger) and an allow-stub authorizer. */
function makeRealRoot(): string {
  const r = makeCliRoot(ROOT, BASE, 'real')
  writeFileSync(join(r, 'scripts', 'hooks', 'email_send_authorize.py'), STUB_HELPER)
  return r
}
function writeEnv(lines: string[]) {
  writeFileSync(join(root, '.env'), lines.map((l) => `${l}\n`).join(''))
}
function ledger(addrs: string[]) {
  writeFileSync(join(root, 'store', 'verified-recipients.json'),
    JSON.stringify({ version: 1, recipients: Object.fromEntries(addrs.map((a) => [a, { source: 'owner' }])) }))
}
function run(rootDir: string, args: string[], scenario: object, env: NodeJS.ProcessEnv = process.env) {
  const n = ++seq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  const r = spawnSync(TSX, [join(rootDir, 'scripts', 'graph-mail.ts'), ...args], {
    cwd: rootDir,
    encoding: 'utf-8',
    timeout: 60_000,
    env: {
      ...env,
      NODE_ENV: 'production',
      MARVEEN_MAIL_CREDS: CREDS,
      GRAPH_MAIL_OUTBOX_DIR: OUTBOX,
      SC_SCENARIO: scenarioPath,
      SC_LOG: logPath,
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(STUB).href}`.trim(),
    },
  })
  const kinds = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8').split('\n').filter(Boolean).map((l) => (JSON.parse(l) as { kind: string }).kind)
    : []
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, kinds }
}
const LETTER = ['send', '--to', 'a@example.com', '--subject', 'Tárgy', '--body', 'Kedves Ügyfél, ez a levél törzse.']
const send = (args: string[] = LETTER, env: NodeJS.ProcessEnv = process.env) => run(root, args, SEND_OK, env)

beforeAll(() => {
  root = makeRealRoot()
})
afterAll(() => {
  rmSync(BASE, { recursive: true, force: true })
})
beforeEach(() => {
  writeEnv([])
  rmSync(join(root, 'store', 'verified-recipients.json'), { force: true })
})

describe('graph-mail.ts and the recipient ledger: off by default', () => {
  it('off: an address not in any ledger goes out (no ledger file at all)', () => {
    const r = send()
    expect(r.status, r.stderr).toBe(0)
    expect(r.kinds).toEqual(['token', 'sendmail'])
  })

  it('off: the step needs no sender_check.py, no gate and no python hook files (regression: it used to refuse every mail)', () => {
    const bare = makeCliRoot(ROOT, BASE, 'stub') // only the two files the forward probe reads, plus the stub authorizer
    expect(existsSync(join(bare, 'scripts', 'hooks', 'sender_check.py'))).toBe(false)
    const r = run(bare, LETTER, SEND_OK)
    expect(r.status, r.stderr).toBe(0)
    expect(r.kinds).toEqual(['token', 'sendmail'])
    const f = run(bare, ['forward', '--id', ID, '--to', 'kovacs@fireeng.hu', '--comment', 'Szia! Kérlek, nézd meg.', '--orig-subject', FWD_SUBJ], FWD_OK)
    expect(f.status, f.stderr).toBe(0)
    expect(f.kinds).toEqual(['token', 'message', 'forward'])
  })

  it('off: a ledger file that would refuse the address is not consulted', () => {
    ledger(['someone-else@example.com'])
    expect(send().status).toBe(0)
  })

  it('an environment variable cannot turn the ledger on (only the install .env does)', () => {
    const r = send(LETTER, { ...process.env, MAIN_AGENT_RECIPIENT_LEDGER: '1' })
    expect(r.status, r.stderr).toBe(0)
    expect(r.kinds).toEqual(['token', 'sendmail'])
  })

  it('an environment variable cannot turn it off either', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    const r = send(LETTER, { ...process.env, MAIN_AGENT_RECIPIENT_LEDGER: '0' })
    expect(r.status).toBe(2)
    expect(r.kinds).toEqual([])
  })
})

describe('graph-mail.ts and the recipient ledger, when the install turns it on', () => {
  it('on: a known address goes out, an unknown --to or --cc is refused before any network call', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    ledger(['a@example.com'])
    const ok = send()
    expect(ok.status, ok.stderr).toBe(0)
    expect(ok.kinds).toEqual(['token', 'sendmail'])
    const r = send([...LETTER, '--cc', 'b@example.org'])
    expect(r.status).toBe(2)
    expect(r.stderr).toContain('REFUSED')
    expect(r.stderr).toContain('b@example.org')
    expect(r.kinds).toEqual([])
    const to = send(['send', '--to', 'x@example.org', '--subject', 'Tárgy', '--body', 'Kedves Ügyfél, ez a levél törzse.'])
    expect(to.status).toBe(2)
    expect(to.kinds).toEqual([])
  })

  it.each(['1', 'true', 'yes', 'on', '"1"', "'On'"])('on: the switch value %s is accepted, as in the gate', (val) => {
    writeEnv([`MAIN_AGENT_RECIPIENT_LEDGER=${val}`])
    ledger([])
    const r = send()
    expect(r.status).toBe(2)
    expect(r.kinds).toEqual([])
  })

  it.each(['0', 'false', 'no', 'off', ''])('the switch value "%s" leaves it off', (val) => {
    writeEnv([`MAIN_AGENT_RECIPIENT_LEDGER=${val}`])
    ledger([])
    expect(send().status).toBe(0)
  })

  it('on: a missing ledger refuses', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    expect(existsSync(join(root, 'store', 'verified-recipients.json'))).toBe(false)
    const r = send()
    expect(r.status).toBe(2)
    expect(r.kinds).toEqual([])
  })

  it('on: a missing sender_check.py refuses (fail-closed)', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    ledger(['a@example.com'])
    const p = join(root, 'scripts', 'hooks', 'sender_check.py')
    const keep = `${p}.keep`
    cpSync(p, keep)
    rmSync(p)
    try {
      const r = send()
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('REFUSED')
      expect(r.kinds).toEqual([])
    } finally {
      cpSync(keep, p)
      rmSync(keep)
    }
  })

  it('on: forward is checked too (a known address goes, an unknown one is refused)', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    ledger(['kovacs@fireeng.hu'])
    const fwd = (to: string) => run(root, ['forward', '--id', ID, '--to', to, '--comment', 'Szia! Kérlek, nézd meg.', '--orig-subject', FWD_SUBJ], FWD_OK)
    const ok = fwd('kovacs@fireeng.hu')
    expect(ok.status, ok.stderr).toBe(0)
    expect(ok.kinds).toEqual(['token', 'message', 'forward'])
    const no = fwd('nagy@fireeng.hu')
    expect(no.status).toBe(2)
    expect(no.stderr).toContain('REFUSED')
    expect(no.kinds).toEqual([])
  })

  it('on: a PATH or PYTHONPATH prefix cannot swap the check for one that always passes', () => {
    writeEnv(['MAIN_AGENT_RECIPIENT_LEDGER=1'])
    ledger([])
    const fake = join(BASE, 'fakebin')
    mkdirSync(fake, { recursive: true })
    writeFileSync(join(fake, 'python3'), '#!/bin/sh\nexit 0\n')
    chmodSync(join(fake, 'python3'), 0o755)
    const site = join(BASE, 'fakesite')
    mkdirSync(site, { recursive: true })
    writeFileSync(join(site, 'sitecustomize.py'), 'import os\nos._exit(0)\n')
    for (const env of [{ ...process.env, PATH: `${fake}:${process.env.PATH}` }, { ...process.env, PYTHONPATH: site }]) {
      const r = send(LETTER, env)
      expect(r.status, r.stderr).toBe(2)
      expect(r.kinds).toEqual([])
    }
  })
})

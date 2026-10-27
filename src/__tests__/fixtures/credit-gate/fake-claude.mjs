// A stand-in for the `claude` binary in the headless-runner tests (card
// fec6335f, N4a; blueprint 6.4). It never talks to a network and never runs
// the real CLI. The tests put a tiny tmp launcher in front of it:
//
//   #!<node>
//   import '<this file>'
//
// so the runner spawns a file in the test's tmp directory, by an absolute
// path, with exactly the environment the runner built (nothing is added).
//
// The prompt arrives on stdin, like the runner sends it. Its first line is the
// test's directive: `FAKE {"mode": ..., "observe": "<abs path>", ...}`. The fake
// writes what it saw to `observe` (argv, the env NAMES, cwd, pid, a sha256 of
// the key it could read -- never the key), then acts out the mode:
//   success          the CLI's JSON result (2.1.299 shape), exit 0
//   credit_too_low   is_error + the API's credit message, exit 1
//   auth_error       is_error + an authentication_error, exit 1
//   nojson_transcript  no JSON; a transcript under $CLAUDE_CONFIG_DIR/projects, exit 1
//   nojson           no JSON, no transcript, exit 1
//   leak             the JSON result, but the key in config/ and its tail in the run dir
//   hang             a grandchild in the same process group; both ignore SIGTERM
//   hang_term        sleeps; exits on SIGTERM (writes "TERM" to observe first)
//   wait_usr2        sleeps; on SIGUSR2 writes the JSON result and exits 0
//   credentials      writes config/.credentials.json (must never be reached)
//   success_orphan   the JSON result, exit 0 -- and a grandchild left running
// directive.result overrides fields of the JSON result; in its `result`
// text, {KEY} becomes the key the fake read (a leak in the model's answer).

import { createRequire } from 'node:module'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const require = createRequire(import.meta.url)
// No non-loopback connect, no 18800/18899 -- self-tested at load (exit 70).
require('./loopback-guard.cjs')
const GUARD = require.resolve('./loopback-guard.cjs')

const argv = process.argv.slice(2)
const stdin = readFileSync(0, 'utf8')
const first = stdin.split('\n', 1)[0]
const directive = first.startsWith('FAKE ') ? JSON.parse(first.slice(5)) : { mode: 'success' }
const mode = directive.mode

function argAfter(flag) {
  const i = argv.indexOf(flag)
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null
}

// The key as Claude Code would get it: from the env, or by running the
// apiKeyHelper of the --settings file. The helper is not executed here; its
// fixed shape `/bin/cat '<path>'` is read instead.
function readKey() {
  if (typeof process.env.ANTHROPIC_API_KEY === 'string') return { key: process.env.ANTHROPIC_API_KEY, source: 'env' }
  const settingsPath = argAfter('--settings')
  if (!settingsPath) return { key: null, source: 'none' }
  const settings = JSON.parse(readFileSync(settingsPath, 'utf8'))
  const m = /^\/bin\/cat '([^']+)'$/.exec(settings.apiKeyHelper ?? '')
  if (!m) return { key: null, source: 'settings-without-helper' }
  return { key: readFileSync(m[1], 'utf8'), source: 'helper' }
}

const { key, source } = readKey()
const observed = {
  argv,
  envNames: Object.keys(process.env).sort(),
  env: Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'ANTHROPIC_API_KEY')),
  cwd: process.cwd(),
  pid: process.pid,
  keySource: source,
  keySha256: key === null ? null : createHash('sha256').update(key).digest('hex'),
  stdinBytes: Buffer.byteLength(stdin),
}

function observe(extra = {}) {
  if (typeof directive.observe === 'string') writeFileSync(directive.observe, JSON.stringify({ ...observed, ...extra }))
}

function result(over = {}) {
  if (typeof over.result === 'string' && key !== null) over = { ...over, result: over.result.split('{KEY}').join(key) }
  return {
    type: 'result',
    subtype: 'success',
    is_error: false,
    duration_ms: 11198,
    num_turns: 3,
    result: 'A synthetic summary of the input file.',
    session_id: '00000000-0000-4000-8000-000000000000',
    total_cost_usd: 0.0749821,
    usage: { input_tokens: 8, cache_creation_input_tokens: 26368, cache_read_input_tokens: 25761, output_tokens: 647 },
    modelUsage: {
      'claude-sonnet-5-5': {
        inputTokens: 8, outputTokens: 647, cacheReadInputTokens: 25761, cacheCreationInputTokens: 26368,
        webSearchRequests: 0, costUSD: 0.0749821, contextWindow: 1000000, maxOutputTokens: 128000, thinkingTokens: 186,
      },
    },
    permission_denials: [],
    ...over,
  }
}

function writeTranscript() {
  const dir = join(process.env.CLAUDE_CONFIG_DIR, 'projects', 'fake-project')
  mkdirSync(dir, { recursive: true })
  const line = (id, out) => JSON.stringify({
    type: 'assistant',
    message: { id, model: 'claude-sonnet-5-5', usage: { input_tokens: 1000, output_tokens: out, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } },
  })
  // Two lines of one tool-calling turn share an id: one response.
  writeFileSync(join(dir, 'session.jsonl'), [line('msg_1', 100), line('msg_1', 100), line('msg_2', 50)].join('\n') + '\n')
}

const sleepForever = () => setInterval(() => {}, 1000)

switch (mode) {
  case 'success':
    observe()
    process.stdout.write(JSON.stringify(result(directive.result ?? {})))
    process.exit(0)
    break
  case 'credit_too_low':
    observe()
    process.stdout.write(JSON.stringify(result({
      is_error: true, total_cost_usd: 0, num_turns: 1, usage: { input_tokens: 0, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, output_tokens: 0 }, modelUsage: {},
      result: 'Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits.',
    })))
    process.exit(1)
    break
  case 'auth_error':
    observe()
    process.stdout.write(JSON.stringify(result({
      is_error: true, total_cost_usd: 0, num_turns: 1, usage: { input_tokens: 0, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, output_tokens: 0 }, modelUsage: {},
      result: 'Failed to authenticate. API Error: 401 {"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}',
    })))
    process.exit(1)
    break
  case 'nojson_transcript':
    observe()
    writeTranscript()
    process.stderr.write('fake: interrupted\n')
    process.exit(1)
    break
  case 'nojson':
    observe()
    process.exit(1)
    break
  case 'leak': {
    observe()
    writeFileSync(join(process.env.CLAUDE_CONFIG_DIR, 'leak.json'), JSON.stringify({ cached: key }))
    writeFileSync(join(dirname(process.env.CLAUDE_CONFIG_DIR), 'stray.txt'), `tail=${key.slice(-20)}\n`)
    process.stdout.write(JSON.stringify(result()))
    process.exit(0)
    break
  }
  case 'hang': {
    process.on('SIGTERM', () => appendFileSync(directive.observe + '.signals', 'TERM\n'))
    const g = spawn(process.execPath, ['--require', GUARD, '-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'], { stdio: 'ignore' })
    observe({ grandchild: g.pid })
    sleepForever()
    break
  }
  case 'hang_term':
    process.on('SIGTERM', () => {
      appendFileSync(directive.observe + '.signals', 'TERM\n')
      process.exit(143)
    })
    observe()
    sleepForever()
    break
  case 'wait_usr2':
    process.on('SIGUSR2', () => {
      process.stdout.write(JSON.stringify(result()))
      process.exit(0)
    })
    observe()
    sleepForever()
    break
  case 'success_orphan': {
    const g = spawn(process.execPath, ['--require', GUARD, '-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
    observe({ grandchild: g.pid })
    process.stdout.write(JSON.stringify(result(directive.result ?? {})))
    process.exit(0)
    break
  }
  case 'credentials':
    observe()
    writeFileSync(join(process.env.CLAUDE_CONFIG_DIR, '.credentials.json'), '{}')
    process.exit(0)
    break
  default:
    process.stderr.write(`fake: unknown mode ${String(mode)}\n`)
    process.exit(2)
}

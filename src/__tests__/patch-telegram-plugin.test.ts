// scripts/patch-telegram-plugin.py (ELSOKOR922 spec D-4): takes /status and
// /help away from the Telegram channel plugin so the command hook can answer
// them. Run for real on a copy of the 0.0.7 plugin excerpt (verbatim blocks,
// fixtures/telegram-plugin-0.0.7/server.ts.txt) in a scratch plugins cache.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, writeFileSync, rmSync, statSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import ts from 'typescript'
import { checkWriteEvidence, findEvidence, readEvidenceLines } from '../web/write-evidence.js'

const ROOT = join(__dirname, '..', '..')
const SCRIPT = join(ROOT, 'scripts', 'patch-telegram-plugin.py')
const FIXTURE = join(__dirname, 'fixtures', 'telegram-plugin-0.0.7', 'server.ts.txt')

let cache = ''
let server = ''

beforeEach(() => {
  cache = mkdtempSync(join(tmpdir(), 'tg-plugin-cache-'))
  const dir = join(cache, 'claude-plugins-official', 'telegram', '0.0.7')
  mkdirSync(dir, { recursive: true })
  server = join(dir, 'server.ts')
  copyFileSync(FIXTURE, server)
})
afterEach(() => rmSync(cache, { recursive: true, force: true }))

function run(extra: string[] = []): { status: number | null; stderr: string } {
  const r = spawnSync('python3', [SCRIPT, ...extra, cache], { encoding: 'utf-8', timeout: 30_000 })
  return { status: r.status, stderr: r.stderr }
}

function readState(file: string): { root: string; files: Array<{ version: string; path: string; status: string; patches: Record<string, string> }> } {
  return JSON.parse(readFileSync(file, 'utf-8'))
}

function syntaxErrors(text: string): string[] {
  const out = ts.transpileModule(text, { reportDiagnostics: true, compilerOptions: { target: ts.ScriptTarget.ES2022 } })
  return (out.diagnostics ?? []).map(d => ts.flattenDiagnosticMessageText(d.messageText, '\n'))
}

describe('patch-telegram-plugin.py', () => {
  it('1st run patches: /help, /status handlers and the plugin menu gone, /start kept, still parses', () => {
    const r = run()
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/patched .*server\.ts/)
    const text = readFileSync(server, 'utf-8')
    expect(text).not.toContain("bot.command('help'")
    expect(text).not.toContain("bot.command('status'")
    expect(text).not.toContain('bot.api.setMyCommands(')
    expect(text).not.toContain('Paired as')
    expect(text).toContain("bot.command('start'")
    expect(text.match(/MARVEEN-PATCH\(elsokor922-d4\)/g)).toHaveLength(3)
    expect(text).toMatch(/ +user_id: String\(from\.id\),\n +\.\.\.\(ctx\.message\?\.forward_origin \? \{ forwarded: '1' \} : \{\}\), \/\/ MARVEEN-PATCH\(elsokor922-fwd\)/)
    expect(syntaxErrors(text)).toEqual([])
  })

  it('2nd run is a no-op: returns `already`, byte-identical, silent', () => {
    const state = join(cache, 'state.json')
    run(['--state', state])
    expect(readState(state).files).toEqual([{ version: '0.0.7', path: server, status: 'patched', patches: { d4: 'patched', fwd: 'patched', evid: 'patched', kbd: 'patched', apv: 'patched' } }])
    const once = readFileSync(server, 'utf-8')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toBe('')
    expect(readFileSync(server, 'utf-8')).toBe(once)
    expect(readState(state).files).toEqual([{ version: '0.0.7', path: server, status: 'already', patches: { d4: 'already', fwd: 'already', evid: 'already', kbd: 'already', apv: 'already' } }])
  })

  it('a changed anchor (plugin update): loud line, THAT patch left out, the other still applied, exit 0', () => {
    const changed = readFileSync(FIXTURE, 'utf-8').replace("bot.command('status', async ctx => {", "bot.command('status', async (ctx) => {")
    writeFileSync(server, changed)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/LOUD: status handler not found exactly once.*the d4 patch left out/)
    const text = readFileSync(server, 'utf-8')
    expect(text).not.toContain('elsokor922-d4')
    expect(text).toContain("bot.command('help', async ctx => {")
    expect(text).toContain('elsokor922-fwd')
    expect(syntaxErrors(text)).toEqual([])
    expect(readState(state).files[0].patches).toEqual({ d4: 'anchor-missing:status handler', fwd: 'patched', evid: 'patched', kbd: 'patched', apv: 'patched' })
  })

  // #1530 review: owner write commands need evidence the owner's chat sent
  // them. The plugin records every inbound message just before handing it to
  // Claude Code -- the one place only a real Telegram update reaches.
  it('evid: one inbound-log line right before the channel notification, and it really writes the record', () => {
    run()
    const text = readFileSync(server, 'utf-8')
    expect(text.match(/MARVEEN-PATCH\(cmd920-evid\)/g)).toHaveLength(1)
    const lines = text.split('\n')
    const i = lines.findIndex(l => l.includes('MARVEEN-PATCH(cmd920-evid)'))
    expect(lines[i + 1]).toMatch(/^ *mcp\.notification\(\{$/)
    expect(lines[i + 2]).toMatch(/method: 'notifications\/claude\/channel',$/)
    expect(syntaxErrors(text)).toEqual([])
    // Run the inserted line with the handler's own names in scope.
    const stateDir = mkdtempSync(join(tmpdir(), 'tg-evid-'))
    try {
      const fs = require('node:fs')
      const fn = new Function('writeFileSync', 'statSync', 'renameSync', 'join', 'STATE_DIR', 'chat_id', 'msgId', 'text', lines[i])
      fn(fs.writeFileSync, fs.statSync, fs.renameSync, join, stateDir, '42', 901, '/model opus')
      fn(fs.writeFileSync, fs.statSync, fs.renameSync, join, stateDir, '42', undefined, 'szia')
      const recs = readFileSync(join(stateDir, 'inbound-evidence.jsonl'), 'utf-8').trim().split('\n').map(l => JSON.parse(l))
      expect(recs.map(r => [r.chat_id, r.message_id, r.text])).toEqual([['42', '901', '/model opus'], ['42', null, 'szia']])
      expect(typeof recs[0].at).toBe('number')
    } finally { rmSync(stateDir, { recursive: true, force: true }) }
  })

  it('evid: the permission notification (a different method) is not an anchor; a moved anchor leaves evid out loudly', () => {
    const changed = readFileSync(FIXTURE, 'utf-8').replace("method: 'notifications/claude/channel',", "method: 'notifications/claude/channel/v2',")
    writeFileSync(server, changed)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.stderr).toMatch(/LOUD: channel notification not found exactly once.*the evid patch left out, no inbound evidence is recorded/)
    expect(readState(state).files[0].patches.evid).toBe('anchor-missing:channel notification')
    expect(readFileSync(server, 'utf-8')).not.toContain('cmd920-evid')
  })

  it('a file patched by the d4-only version gets the forward patch on the next run', () => {
    run()
    const d4only = readFileSync(server, 'utf-8').replace(/\n +\.\.\.\(ctx\.message\?\.forward_origin[^\n]*/, '')
    writeFileSync(server, d4only)
    expect(d4only).not.toContain('elsokor922-fwd')
    const r = run()
    expect(r.stderr).toMatch(/patched .*\(fwd\)/)
    expect(readFileSync(server, 'utf-8').match(/elsokor922-fwd/g)).toHaveLength(1)
  })

  it('writes exactly one cache: $CLAUDE_CONFIG_DIR when set, the user-level ~/.claude never on top', () => {
    const home = mkdtempSync(join(tmpdir(), 'tg-plugin-home-'))
    try {
      const userDir = join(home, '.claude', 'plugins', 'cache', 'claude-plugins-official', 'telegram', '0.0.7')
      mkdirSync(userDir, { recursive: true })
      const userServer = join(userDir, 'server.ts')
      copyFileSync(FIXTURE, userServer)
      // cache = <cfg>/plugins/cache, so its config dir is two levels up
      const cfg = join(cache, 'cfg')
      const cfgDir = join(cfg, 'plugins', 'cache', 'claude-plugins-official', 'telegram', '0.0.7')
      mkdirSync(cfgDir, { recursive: true })
      const cfgServer = join(cfgDir, 'server.ts')
      copyFileSync(FIXTURE, cfgServer)
      const env = { ...process.env, HOME: home, CLAUDE_CONFIG_DIR: cfg }
      const r = spawnSync('python3', [SCRIPT], { encoding: 'utf-8', env })
      expect(r.status).toBe(0)
      expect(readFileSync(cfgServer, 'utf-8')).toContain('MARVEEN-PATCH(elsokor922-d4)')
      expect(readFileSync(userServer, 'utf-8')).toBe(readFileSync(FIXTURE, 'utf-8'))
      // without CLAUDE_CONFIG_DIR the user-level cache IS the launch cache
      const { CLAUDE_CONFIG_DIR: _unset, ...noCfg } = env
      spawnSync('python3', [SCRIPT], { encoding: 'utf-8', env: noCfg })
      expect(readFileSync(userServer, 'utf-8')).toContain('MARVEEN-PATCH(elsokor922-d4)')
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('no plugin cache at all: exit 0, nothing to do', () => {
    const r = spawnSync('python3', [SCRIPT, join(cache, 'does-not-exist')], { encoding: 'utf-8' })
    expect(r.status).toBe(0)
  })

  it('an unwritable file: named in the log, exit 0 (the channel still starts)', () => {
    const dir = join(cache, 'claude-plugins-official', 'telegram', '0.0.7')
    spawnSync('chmod', ['a-w', dir])
    try {
      const r = run()
      expect(r.status).toBe(0)
      expect(r.stderr).toMatch(/cannot write .*left unpatched/)
      expect(readFileSync(server, 'utf-8')).toBe(readFileSync(FIXTURE, 'utf-8'))
    } finally {
      spawnSync('chmod', ['u+w', dir])
    }
  })
})

// c67f5f34: one-tap answer buttons on the reply tool, as an INLINE keyboard under the message. A tap comes back as the
// label in an ordinary text message. Six marked insertions: the schema field, its check before anything is sent, the
// inline keyboard on the LAST text chunk, the Set of answered messages, the kbd branch of the callback handler, and the
// ts / message_id of the inbound meta of a tap. (The behaviour of the callback branch itself: the callback tests below
// the patch mechanics.)
const KBD = 'MARVEEN-PATCH(c67f5f34-kbd)'
const KBD_MARKER = '// MARVEEN-PATCH(c67f5f34-kbd): one-tap answer buttons'
// The live apv patch (PR #1964) line, word for word: it must sit right after the `const data` line.
const APV_LINE = "  if (data.startsWith('apv:')) { await marveenApprovalCallback(ctx, data, { stateDir: STATE_DIR, readFileSync, fetch, loadAccess, env: process.env, envAtLoad: MARVEEN_APV_ENV_AT_LOAD }); return } // MARVEEN-PATCH(345f34e2-apv)"
const CALLBACK_OPEN = "bot.on('callback_query:data', async ctx => {"

// The three lines of the FIRST version (the reply keyboard, commit 6eec41a2), as the old script wrote them into the
// fixture. Kept as literals, not generated from the script.
const OLD_KBD_SCHEMA = "          buttons: { type: 'array', items: { type: 'string' }, description: 'Optional one-tap answer buttons, shown as a keyboard under the input field and hidden after one tap; the tapped label comes back as an ordinary text message from the user. Also write the options into text, so the question can be answered by typing. An empty list removes a keyboard shown earlier. At most 12 labels, each non-empty and at most 64 characters.' }, // MARVEEN-PATCH(c67f5f34-kbd): one-tap answer buttons"
const OLD_KBD_CHECK = "        const kbdButtons = args.buttons == null ? undefined : Array.isArray(args.buttons) && args.buttons.length <= 12 && args.buttons.every(b => typeof b === 'string' && b.trim() !== '' && b.length <= 64) ? (args.buttons as string[]) : (() => { throw new Error('buttons: a list of at most 12 non-empty labels, each at most 64 characters') })() // MARVEEN-PATCH(c67f5f34-kbd): one-tap answer buttons"
const OLD_KBD_SEND = "              ...(kbdButtons && i === chunks.length - 1 ? { reply_markup: kbdButtons.length ? { keyboard: kbdButtons.map(label => [{ text: label }]), one_time_keyboard: true, resize_keyboard: true } : { remove_keyboard: true as const } } : {}), // MARVEEN-PATCH(c67f5f34-kbd): one-tap answer buttons"

const kbdLines = (text: string): string[] => text.split('\n').filter(l => l.includes(KBD))

// The fixture patched by the script WITHOUT the kbd patch (the state a file had before this change).
function patchedWithoutKbd(text: string, topics = false): string {
  const code = [
    'import importlib.util, sys',
    "spec = importlib.util.spec_from_file_location('ptp', sys.argv[1])",
    'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
    "m.PATCHES = [p for p in m.PATCHES if p['name'] != 'kbd']",
    "sys.stdout.write(m.patch_text(sys.stdin.read(), sys.argv[2] == 'on')[0])",
  ].join('\n')
  const r = spawnSync('python3', ['-c', code, SCRIPT, topics ? 'on' : 'off'], { input: text, encoding: 'utf-8' })
  expect(r.status).toBe(0)
  return r.stdout
}

// The file as the FIRST kbd version left it: the three old lines put after the same anchors.
function withOldKbd(text: string): string {
  const lines = patchedWithoutKbd(text).split('\n')
  const after = (re: RegExp, extra: number, add: string) => {
    const i = lines.findIndex(l => re.test(l))
    expect(i).toBeGreaterThan(0)
    lines.splice(i + 1 + extra, 0, add)
  }
  after(/^ *description: 'Absolute file paths to attach\. /, 1, OLD_KBD_SCHEMA) // after the `},` that closes `files`
  after(/^ *assertAllowedChat\(chat_id\)$/, 0, OLD_KBD_CHECK)
  after(/^ *\.\.\.\(parseMode \? \{ parse_mode: parseMode \} : \{\}\),$/, 0, OLD_KBD_SEND)
  return lines.join('\n')
}

type Sent = { chat: string; text: string; opts: Record<string, unknown> }

// Runs the PATCHED tool-call handler of the fixture (the verbatim 0.0.7 block) with a fake bot: what the reply tool
// really passes to sendMessage. Only the reply case runs; the names the other cases use are never evaluated.
// `allowFrom` is what loadAccess() says: the chat ids (= user ids) the buttons may go to.
function replyHandler(patched: string, allowFrom: string[] = ['42']): { call: (args: Record<string, unknown>) => Promise<{ isError?: boolean; content: Array<{ text: string }> }>; sent: Sent[] } {
  const start = patched.indexOf('mcp.setRequestHandler(CallToolRequestSchema')
  expect(start).toBeGreaterThan(0)
  const js = ts.transpileModule(patched.slice(start), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const sent: Sent[] = []
  let handler: ((req: unknown) => Promise<never>) | undefined
  const mcp = { setRequestHandler: (_schema: unknown, fn: (req: unknown) => Promise<never>) => { handler = fn } }
  const bot = { api: { sendMessage: async (chat: string, text: string, opts: Record<string, unknown>) => { sent.push({ chat, text, opts }); return { message_id: sent.length } } } }
  const names = ['mcp', 'CallToolRequestSchema', 'assertAllowedChat', 'assertSendable', 'statSync', 'MAX_ATTACHMENT_BYTES',
    'loadAccess', 'MAX_CHUNK_LIMIT', 'chunk', 'bot', 'extname', 'InputFile', 'PHOTO_EXTS', 'PERMISSION_REPLY_RE']
  new Function(...names, js)(mcp, {}, () => {}, () => {}, () => ({ size: 0 }), 50 * 1024 * 1024,
    () => ({ allowFrom }), 4096, (text: string) => text.split('|'), bot, () => '', class {}, new Set(),
    /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i)
  expect(handler).toBeDefined()
  return { call: args => handler!({ params: { name: 'reply', arguments: args } }), sent }
}

describe('kbd: inline answer buttons (c67f5f34)', () => {
  it('every inserted line carries the marker at its end; the buttons field is inside the reply tool schema; the file still parses', () => {
    expect(run().status).toBe(0)
    const text = readFileSync(server, 'utf-8')
    const lines = kbdLines(text)
    expect(lines).toHaveLength(23)
    for (const l of lines) expect(l.endsWith(' ' + KBD_MARKER)).toBe(true)
    const reply = text.indexOf("name: 'reply'")
    const react = text.indexOf("name: 'react'")
    const field = text.indexOf("buttons: { type: 'array'")
    expect(field).toBeGreaterThan(reply)
    expect(field).toBeLessThan(text.indexOf("required: ['chat_id', 'text'],", reply))
    expect(react).toBeGreaterThan(field)
    expect(text).not.toContain('one_time_keyboard')
    expect(text).not.toContain('resize_keyboard')
    expect(text).toContain("callback_data: 'kbd:' + n")
    expect(syntaxErrors(text)).toEqual([])
  })

  it('the Set sits right after PERMISSION_REPLY_RE; the callback branch right after the perm regex, before `if (!m) {`', () => {
    run()
    const lines = readFileSync(server, 'utf-8').split('\n')
    const re = lines.findIndex(l => l.startsWith('const PERMISSION_REPLY_RE = '))
    expect(lines[re + 1]).toBe(`const marveenKbdAnswered = new Set<string>() ${KBD_MARKER}`)
    const perm = lines.findIndex(l => l.startsWith('  const m = /^perm:'))
    expect(lines[perm + 1]).toBe(`  if (data.startsWith('kbd:')) { ${KBD_MARKER}`)
    const close = lines.findIndex((l, i) => i > perm && l === `  } ${KBD_MARKER}`)
    expect(lines[close + 1]).toBe('  if (!m) {')
    for (let i = perm + 1; i <= close; i++) expect(lines[i].endsWith(KBD_MARKER)).toBe(true)
  })

  it('the reply sends the inline keyboard on the LAST chunk only, one label per row, callback_data kbd:<index>', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'))
    const res = await h.call({ chat_id: '42', text: 'Első rész|A: elfogadod, B: már megoldva, C: más megoldás?', buttons: ['A. Elfogadom', 'B. Már megoldva', 'C. Valami más lesz a megoldás'] })
    expect(res.isError).toBeUndefined()
    expect(h.sent).toHaveLength(2)
    expect(h.sent[0].opts).not.toHaveProperty('reply_markup')
    expect(h.sent[1].opts.reply_markup).toEqual({
      inline_keyboard: [
        [{ text: 'A. Elfogadom', callback_data: 'kbd:0' }],
        [{ text: 'B. Már megoldva', callback_data: 'kbd:1' }],
        [{ text: 'C. Valami más lesz a megoldás', callback_data: 'kbd:2' }],
      ],
    })
  })

  it('markdownv2: the parse_mode stays in the same options object as the keyboard', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'))
    await h.call({ chat_id: '42', text: '*Kérdés*', format: 'markdownv2', buttons: ['Igen', 'Nem'] })
    expect(h.sent[0].opts.parse_mode).toBe('MarkdownV2')
    expect(h.sent[0].opts.reply_markup).toEqual({ inline_keyboard: [[{ text: 'Igen', callback_data: 'kbd:0' }], [{ text: 'Nem', callback_data: 'kbd:1' }]] })
  })

  it('an empty list removes a keyboard shown earlier; no buttons means no reply_markup at all', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'))
    await h.call({ chat_id: '42', text: 'Köszönöm, rögzítettem.', buttons: [] })
    expect(h.sent[0].opts.reply_markup).toEqual({ remove_keyboard: true })
    await h.call({ chat_id: '42', text: 'Sima válasz|két részben' })
    expect(h.sent.slice(1).map(s => 'reply_markup' in s.opts)).toEqual([false, false])
  })

  it('a bad buttons value is a tool error BEFORE anything is sent; the limits themselves are accepted', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'))
    const bad: unknown[] = ['A', [''], ['   '], [1], ['x'.repeat(65)], Array.from({ length: 13 }, (_, i) => `${i}`)]
    for (const buttons of bad) {
      const res = await h.call({ chat_id: '42', text: 'Kérdés', buttons })
      expect(res.isError).toBe(true)
      expect(res.content[0].text).toMatch(/^reply failed: buttons: /)
    }
    expect(h.sent).toHaveLength(0)
    const ok = await h.call({ chat_id: '42', text: 'Kérdés', buttons: [...Array.from({ length: 11 }, (_, i) => `${i}`), 'x'.repeat(64)] })
    expect(ok.isError).toBeUndefined()
  })

  it('a label that could pass for a command, a control character or a permission reply is refused before sending; A/B and 1/2 are fine', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'))
    const ch = (code: number) => String.fromCharCode(code)
    const bad = ['/model opus', ' /x', '\t/x', ch(0x200b) + '/x', ch(0xfeff) + '/x', ch(0x1c) + '/x', '(/x', 'a\nb', 'a' + ch(0) + 'b', 'a' + ch(0x85) + 'b',
      'yes abcde', 'No abcde', '  y abcde  ']
    for (const label of bad) {
      const res = await h.call({ chat_id: '42', text: 'Kérdés', buttons: ['Rendben', label] })
      expect(res.isError, JSON.stringify(label)).toBe(true)
      expect(res.content[0].text, JSON.stringify(label)).toMatch(/^reply failed: buttons: /)
    }
    expect(h.sent).toHaveLength(0)
    for (const label of ['A/B', '1/2', 'Igen / nem', 'yes', 'no abc']) {
      const res = await h.call({ chat_id: '42', text: 'Kérdés', buttons: [label] })
      expect(res.isError, JSON.stringify(label)).toBeUndefined()
    }
    expect(h.sent).toHaveLength(5)
  })

  it('buttons go to a private chat of a paired user only; a group (or an unknown chat) gets a tool error, an empty list is still fine', async () => {
    run()
    const h = replyHandler(readFileSync(server, 'utf-8'), ['42'])
    for (const chat_id of ['-1001234567890', '77']) {
      const res = await h.call({ chat_id, text: 'Kérdés', buttons: ['Igen'] })
      expect(res.isError).toBe(true)
      expect(res.content[0].text).toMatch(/^reply failed: buttons: /)
    }
    expect(h.sent).toHaveLength(0)
    const ok = await h.call({ chat_id: '-1001234567890', text: 'Szöveg', buttons: [] })
    expect(ok.isError).toBeUndefined()
    expect(h.sent).toHaveLength(1)
  })

  it('the inbound meta of a tap: a fresh ts and the id of the question; a typed message keeps its meta (the line adds nothing)', () => {
    run()
    const line = kbdLines(readFileSync(server, 'utf-8')).find(l => l.includes('ts: new Date().toISOString()'))
    expect(line).toBeDefined()
    const meta = new Function('ctx', `return {\n${line}\n}`)
    const tap = meta({ callbackQuery: { message: { message_id: 901 } } })
    expect(tap.message_id).toBe('901')
    expect(Math.abs(Date.now() - Date.parse(tap.ts))).toBeLessThan(5000)
    expect(meta({ message: { message_id: 5, date: 1 } })).toEqual({})
    expect(meta({ callbackQuery: {} })).toEqual({})
  })

  it('taking it back = deleting the marked lines: byte-identical to the file patched without kbd', () => {
    run()
    const withKbd = readFileSync(server, 'utf-8')
    const back = withKbd.split('\n').filter(l => !l.includes(KBD)).join('\n')
    expect(back).toBe(patchedWithoutKbd(readFileSync(FIXTURE, 'utf-8')))
    expect(back).not.toContain(KBD)
  })

  it('all or nothing: one moved kbd anchor leaves every kbd line out, loudly; the other patches still applied', () => {
    const changed = readFileSync(FIXTURE, 'utf-8').replace('...(parseMode ? { parse_mode: parseMode } : {}),', '...(parseMode ? { parse_mode: parseMode } : undefined),')
    writeFileSync(server, changed)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/LOUD: reply send options not found exactly once.*the kbd patch left out, the reply tool has no buttons/)
    expect(readFileSync(server, 'utf-8')).not.toContain(KBD)
    expect(readState(state).files[0].patches).toEqual({ d4: 'patched', fwd: 'patched', evid: 'patched', kbd: 'anchor-missing:reply send options', apv: 'patched' })
  })

  it('each of the three new anchors, when moved, leaves every kbd line out on a fresh file', () => {
    const moved: Array<[string, string, string]> = [
      ['permission reply regex', 'const PERMISSION_REPLY_RE = ', 'const PERMISSION_REPLY_RE_2 = '],
      ['callback perm regex', 'const m = /^perm:', 'const mm = /^perm:'],
      ['inbound meta imagePath', '...(imagePath ? { image_path: imagePath } : {}),', '...(imagePath ? { image_path: imagePath } : undefined),'],
    ]
    for (const [name, from, to] of moved) {
      const changed = readFileSync(FIXTURE, 'utf-8').replace(from, to)
      expect(changed).not.toBe(readFileSync(FIXTURE, 'utf-8'))
      writeFileSync(server, changed)
      const state = join(cache, `state-${name.replace(/ /g, '-')}.json`)
      const r = run(['--state', state])
      expect(r.stderr).toMatch(new RegExp(`LOUD: ${name} not found exactly once.*the kbd patch left out`))
      expect(readFileSync(server, 'utf-8')).not.toContain(KBD)
      expect(readState(state).files[0].patches.kbd).toBe(`anchor-missing:${name}`)
    }
  })

  it('a file patched by the previous version (d4, fwd, evid) gets kbd on the next run', () => {
    writeFileSync(server, patchedWithoutKbd(readFileSync(FIXTURE, 'utf-8')))
    const r = run()
    expect(r.stderr).toMatch(/patched .*\(kbd\)/)
    expect(kbdLines(readFileSync(server, 'utf-8'))).toHaveLength(23)
  })

  it('a file with the FIRST kbd version (reply keyboard) is rebuilt in place: byte-identical to a fresh patching, no old line left', () => {
    run()
    const fresh = readFileSync(server, 'utf-8')
    const old = withOldKbd(readFileSync(FIXTURE, 'utf-8'))
    expect(kbdLines(old)).toHaveLength(3)
    expect(old).toContain('one_time_keyboard')
    writeFileSync(server, old)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/patched .*\(kbd\)/)
    const text = readFileSync(server, 'utf-8')
    expect(text).toBe(fresh)
    expect(text).not.toContain('one_time_keyboard')
    expect(text).not.toContain('resize_keyboard')
    expect(readState(state).files[0].patches.kbd).toBe('patched')
    // and the next run leaves it alone
    const again = run()
    expect(again.stderr).toBe('')
    expect(readFileSync(server, 'utf-8')).toBe(fresh)
  })

  it('a file with the first kbd version and a moved new anchor keeps the old lines untouched, loudly', () => {
    const changed = readFileSync(FIXTURE, 'utf-8').replace('const m = /^perm:', 'const mm = /^perm:')
    const old = withOldKbd(changed)
    writeFileSync(server, old)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/LOUD: callback perm regex not found exactly once.*the kbd patch left out/)
    expect(readFileSync(server, 'utf-8')).toBe(old)
    expect(readState(state).files[0].patches.kbd).toBe('anchor-missing:callback perm regex')
  })

  it('a kbd marker not at the end of a line: damaged, the file is not touched, loudly', () => {
    run()
    const text = readFileSync(server, 'utf-8')
    const damaged = text.replace(`${KBD_MARKER}\n`, `${KBD_MARKER} (edited)\n`)
    expect(damaged).not.toBe(text)
    writeFileSync(server, damaged)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/LOUD: kbd markers damaged in .*the kbd patch left alone/)
    expect(readFileSync(server, 'utf-8')).toBe(damaged)
    const file = readState(state).files[0]
    expect(file.patches.kbd).toBe('damaged:kbd markers')
    expect(file.status).toBe('damaged:kbd markers')
  })

  it('topics on, off and on again: kbd is `already` every time after the first run, and the ts override stays right before the imagePath line', () => {
    const state = join(cache, 'state.json')
    run(['--topics', 'on', '--state', state])
    const withTopics = readFileSync(server, 'utf-8')
    const lines = withTopics.split('\n')
    const i = lines.findIndex(l => l.includes('ts: new Date().toISOString()') && l.includes(KBD))
    expect(lines[i + 1].trim()).toBe('...(imagePath ? { image_path: imagePath } : {}),')
    expect(withTopics).toContain('MARVEEN-PATCH(tgtopics)')
    const again = run(['--topics', 'on', '--state', state])
    expect(again.stderr).toBe('')
    expect(readState(state).files[0].patches.kbd).toBe('already')
    expect(readFileSync(server, 'utf-8')).toBe(withTopics)
    run(['--topics', 'off', '--state', state])
    expect(readState(state).files[0].patches.kbd).toBe('already')
    const off = readFileSync(server, 'utf-8')
    expect(off).not.toContain('MARVEEN-PATCH(tgtopics)')
    expect(kbdLines(off)).toHaveLength(23)
    const offAgain = run(['--topics', 'off', '--state', state])
    expect(offAgain.stderr).toBe('')
    run(['--topics', 'on', '--state', state])
    expect(readFileSync(server, 'utf-8')).toBe(withTopics)
    expect(readState(state).files[0].patches.kbd).toBe('already')
  })

  it('topics first, kbd second gives the same file as kbd first, topics second', () => {
    run(['--topics', 'on'])
    const kbdFirst = readFileSync(server, 'utf-8')
    writeFileSync(server, patchedWithoutKbd(readFileSync(FIXTURE, 'utf-8'), true))
    run(['--topics', 'on'])
    expect(readFileSync(server, 'utf-8')).toBe(kbdFirst)
  })

  it('with the apv hook line (PR #1964) after `const data`: kbd goes in after the perm regex and leaves that stretch alone, in both patch orders', () => {
    const hook = (text: string) => {
      const lines = text.split('\n')
      const open = lines.indexOf(CALLBACK_OPEN)
      expect(open).toBeGreaterThan(0)
      return { lines, open }
    }
    const fixtureText = readFileSync(FIXTURE, 'utf-8')
    // apv first, kbd second
    const withApv = fixtureText.replace(`${CALLBACK_OPEN}\n  const data = ctx.callbackQuery.data\n`, `${CALLBACK_OPEN}\n  const data = ctx.callbackQuery.data\n${APV_LINE}\n`)
    expect(withApv).not.toBe(fixtureText)
    writeFileSync(server, withApv)
    const r = run()
    expect(r.stderr).toMatch(/patched .*\(.*kbd.*\)/)
    const first = readFileSync(server, 'utf-8')
    const a = hook(first)
    expect(a.lines.slice(a.open + 1, a.open + 4)).toEqual([
      '  const data = ctx.callbackQuery.data',
      APV_LINE,
      expect.stringMatching(/^ {2}const m = \/\^perm:/),
    ])
    expect(a.lines[a.open + 4]).toBe(`  if (data.startsWith('kbd:')) { ${KBD_MARKER}`)
    expect(syntaxErrors(first)).toEqual([])
    // kbd first, the apv line put in afterwards (as the apv patch does): the next kbd run changes nothing
    writeFileSync(server, fixtureText)
    run()
    const kbdOnly = readFileSync(server, 'utf-8')
    const b = hook(kbdOnly)
    expect(b.lines[b.open + 2]).toMatch(/^ {2}const m = \/\^perm:/)
    const lines = [...b.lines]
    lines.splice(b.open + 2, 0, APV_LINE)
    writeFileSync(server, lines.join('\n'))
    const state = join(cache, 'state.json')
    const r2 = run(['--state', state])
    expect(r2.stderr).toBe('')
    expect(readState(state).files[0].patches.kbd).toBe('already')
    expect(readFileSync(server, 'utf-8')).toBe(first)
  })
})

// Card 2676132e, N2: the BEHAVIOUR of what the kbd patch inserted. The patched callback_query:data handler and the
// patched handleInbound are cut out of the patched fixture (the verbatim plugin blocks plus the marked lines), transpiled
// and run with fakes for everything they reach for: loadAccess, gate, saveAccess, the grammY ctx, mcp, the Telegram API.
// A restart of the plugin = a harness with a new marveenKbdAnswered Set (the declaration line is taken from the file).
type Btn = { text: string; callback_data?: string; url?: string }
type Toast = { text?: string } | undefined
type FakeCtx = Record<string, unknown>
type InboundFn = (ctx: FakeCtx, text: string, img: undefined) => Promise<void>

interface TapSpec {
  data: string
  fromId?: number | null // null: the update has no `from`
  chat?: { id: number; type: string }
  messageId?: number
  markup?: Btn[][] // the inline keyboard the message carries (default: Alfa, Béta, Gamma as kbd:0..2)
  inaccessible?: boolean // an InaccessibleMessage: chat and message_id, no reply_markup
  noMessage?: boolean // no callbackQuery.message at all
  edit?: 'ok' | 'fail' // what editMessageReplyMarkup does
  answerFails?: boolean // answerCallbackQuery rejects (network)
}

const kb = (...labels: string[]): Btn[][] => labels.map((text, i) => [{ text, callback_data: 'kbd:' + i }])
const NOT_ALLOWED = 'Nem engedélyezett.'
const ALREADY = 'Erre már válaszoltál.'
const DEAD = 'Ez a gomb már nem él, írd be a választ.'
const NOT_RECORDED = 'Nem sikerült rögzíteni, írd be a választ.'

function transpile(code: string): string {
  return ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
}

function callbackHarness(patched: string, o: { allowFrom?: string[]; handleInbound?: InboundFn } = {}) {
  const setLine = patched.split('\n').find(l => l.startsWith('const marveenKbdAnswered = '))
  expect(setLine).toBeDefined()
  expect(syntaxErrors(setLine!)).toEqual([])
  const start = patched.indexOf("bot.on('callback_query:data'")
  const end = patched.indexOf('async function handleInbound(')
  expect(start).toBeGreaterThan(0)
  expect(end).toBeGreaterThan(start)
  expect(patched.indexOf(setLine!)).toBeLessThan(start) // module level, ahead of the handler
  const js = transpile(setLine + '\n' + patched.slice(start, end))
  const events: string[] = []
  const delivered: Array<{ ctx: FakeCtx; text: string; img: unknown }> = []
  const gateCalls: unknown[][] = []
  const saveCalls: unknown[][] = []
  const permNotifications: unknown[] = []
  const approvals: string[] = []
  const pendingPermissions = new Map<string, { tool_name: string; description: string; input_preview: string }>()
  let handler: ((ctx: FakeCtx) => Promise<void>) | undefined
  const bot = { on: (_ev: string, fn: (ctx: FakeCtx) => Promise<void>) => { handler = fn } }
  const handleInbound: InboundFn = async (ctx, text, img) => {
    events.push('deliver')
    delivered.push({ ctx, text, img })
    if (o.handleInbound) await o.handleInbound(ctx, text, img)
  }
  const mcp = { notification: (n: unknown) => { permNotifications.push(n); return Promise.resolve() } }
  class InlineKeyboard { text() { return this } }
  const set = new Function('bot', 'loadAccess', 'handleInbound', 'pendingPermissions', 'mcp', 'InlineKeyboard', 'gate', 'saveAccess',
    'marveenApprovalCallback', 'STATE_DIR', 'readFileSync', 'fetch', 'MARVEEN_APV_ENV_AT_LOAD', 'PERMISSION_REPLY_RE', js + '\nreturn marveenKbdAnswered')(
    bot, () => ({ allowFrom: o.allowFrom ?? ['42'] }), handleInbound, pendingPermissions, mcp, InlineKeyboard,
    (...a: unknown[]) => { gateCalls.push(a); return { action: 'pair', code: 'abc123' } },
    (...a: unknown[]) => { saveCalls.push(a) },
    async (_ctx: FakeCtx, data: string) => { approvals.push(data) }, '/scratch-state', () => '',
    () => { throw new Error('no network in a test') }, {}, /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i) as Set<string>
  expect(handler).toBeDefined()
  expect(set).toBeInstanceOf(Set)

  const press = async (t: TapSpec) => {
    const answers: Toast[] = []
    const edits: unknown[] = []
    const textEdits: unknown[] = []
    const chat = t.chat ?? { id: 42, type: 'private' }
    const message = t.noMessage ? undefined : {
      message_id: t.messageId ?? 901,
      chat,
      ...(t.inaccessible ? { date: 0 } : { text: 'Kérdés', reply_markup: { inline_keyboard: t.markup ?? kb('Alfa', 'Béta', 'Gamma') } }),
    }
    const ctx: FakeCtx = {
      callbackQuery: { data: t.data, ...(message ? { message } : {}) },
      from: t.fromId === null ? undefined : { id: t.fromId ?? 42, username: 'owner' },
      chat: message?.chat,
      answerCallbackQuery: async (a?: { text?: string }) => { answers.push(a); events.push('answer'); if (t.answerFails) throw new Error('network down') },
      editMessageReplyMarkup: async (a: unknown) => { edits.push(a); events.push('edit'); if (t.edit === 'fail') throw new Error('400 Bad Request: message is not modified') },
      editMessageText: async (...a: unknown[]) => { textEdits.push(a); events.push('editText') },
    }
    await handler!(ctx)
    return { ctx, answers, edits, textEdits }
  }
  return { press, set, events, delivered, gateCalls, saveCalls, permNotifications, approvals, pendingPermissions }
}
type Harness = ReturnType<typeof callbackHarness>
type PressResult = Awaited<ReturnType<Harness['press']>>

// A press that must change nothing: one toast with exactly this text, no edit, no delivery, no gate (pairing), no
// saveAccess, no approval or permission side effect, nothing in the Set.
function expectToastOnly(h: Harness, r: PressResult, text: string, what: string): void {
  expect(r.answers, what).toEqual([{ text }])
  expect(r.edits, what).toHaveLength(0)
  expect(r.textEdits, what).toHaveLength(0)
  expect(h.delivered, what).toHaveLength(0)
  expect(h.gateCalls, what).toHaveLength(0)
  expect(h.saveCalls, what).toHaveLength(0)
  expect(h.permNotifications, what).toHaveLength(0)
  expect(h.approvals, what).toHaveLength(0)
  expect(h.set.size, what).toBe(0)
}

type Notification = { method: string; params: { content: string; meta: Record<string, string> } }
type EvidenceRec = { chat_id: string; message_id: string | null; text: string; at: number }

// The PATCHED handleInbound of the fixture with a gate that delivers (what gate() says for a paired owner in a private chat).
function inboundHarness(patched: string, stateDir: string) {
  const start = patched.indexOf('async function handleInbound(')
  const end = patched.indexOf('// --- Server instructions')
  expect(start).toBeGreaterThan(0)
  expect(end).toBeGreaterThan(start)
  const notifications: Notification[] = []
  const mcp = { notification: (n: Notification) => { notifications.push(n); return Promise.resolve() } }
  const bot = { api: { sendChatAction: async () => {}, setMessageReaction: async () => {} } }
  const handleInbound = new Function('gate', 'PERMISSION_REPLY_RE', 'mcp', 'bot', 'STATE_DIR', 'join', 'writeFileSync', 'statSync', 'renameSync',
    transpile(patched.slice(start, end)) + '\nreturn handleInbound')(
    () => ({ action: 'deliver', access: {} }), /^\s*(y|yes|n|no)\s+([a-km-z]{5})\s*$/i, mcp, bot, stateDir, join, writeFileSync, statSync, renameSync) as InboundFn
  const evidence = (): EvidenceRec[] => readEvidenceLines(stateDir).filter(l => l !== '').map(l => JSON.parse(l) as EvidenceRec)
  return { handleInbound, notifications, evidence }
}

describe('kbd: the callback branch and the delivery of a tap (c67f5f34, card 2676132e N2)', () => {
  let patched = ''
  let stateDir = ''
  beforeEach(() => {
    expect(run(['--topics', 'off']).status).toBe(0)
    patched = readFileSync(server, 'utf-8')
    stateDir = mkdtempSync(join(tmpdir(), 'tg-kbd-evid-'))
  })
  afterEach(() => rmSync(stateDir, { recursive: true, force: true }))

  it('AC-C1: a stranger (not in allowFrom) gets the toast only: no delivery, no edit, no gate/pairing, no saveAccess, no Set entry', async () => {
    const h = callbackHarness(patched, { allowFrom: ['42'] })
    const strangers: TapSpec[] = [
      { data: 'kbd:0', fromId: 99, chat: { id: 99, type: 'private' } },
      { data: 'kbd:1', fromId: 99, chat: { id: 99, type: 'private' }, markup: kb('A', 'B') },
      { data: 'kbd:0', fromId: 99, chat: { id: 99, type: 'private' }, messageId: 5 },
      { data: 'kbd:12', fromId: 99, chat: { id: 99, type: 'private' } }, // forged data does not get a different answer
      { data: 'kbd:-', fromId: 99, chat: { id: 99, type: 'private' }, markup: [[{ text: '✓ Alfa', callback_data: 'kbd:-' }]] },
    ]
    for (const t of strangers) {
      const r = await h.press(t)
      expectToastOnly(h, r, NOT_ALLOWED, JSON.stringify(t))
    }
    // the owner himself when nobody is paired
    const empty = callbackHarness(patched, { allowFrom: [] })
    expectToastOnly(empty, await empty.press({ data: 'kbd:0' }), NOT_ALLOWED, 'empty allowFrom')
  })

  it('AC-C1: no `from`, no message, or an update without the message the keyboard sits on: the same refusal (fail closed)', async () => {
    const h = callbackHarness(patched)
    expectToastOnly(h, await h.press({ data: 'kbd:0', fromId: null }), NOT_ALLOWED, 'no from')
    expectToastOnly(h, await h.press({ data: 'kbd:0', noMessage: true }), NOT_ALLOWED, 'no message')
  })

  it('AC-C2: the owner in a group, a supergroup, a channel, or a chat that is not his own: the same toast, nothing else', async () => {
    const h = callbackHarness(patched, { allowFrom: ['42'] })
    const chats: Array<{ id: number; type: string }> = [
      { id: -1001234567890, type: 'supergroup' },
      { id: -555, type: 'group' },
      { id: -100777, type: 'channel' },
      { id: 42, type: 'group' }, // an id equal to his, but not a private chat
      { id: 77, type: 'private' }, // a private chat, but chat.id !== from.id
      { id: 4242, type: 'private' },
    ]
    for (const chat of chats) {
      const r = await h.press({ data: 'kbd:0', fromId: 42, chat })
      expectToastOnly(h, r, NOT_ALLOWED, JSON.stringify(chat))
    }
  })

  it('AC-C3: forged data (out-of-range index, leading zero, sign, junk, trailing space/newline, hex, digits that are not ASCII, nested prefixes) gets the dead-button toast only, even when the keyboard itself carries that data', async () => {
    const h = callbackHarness(patched)
    const forged = ['kbd:12', 'kbd:01', 'kbd:00', 'kbd:-1', 'kbd:+1', 'kbd:', 'kbd:a', 'kbd:1 ', 'kbd:1\n', 'kbd:0\n', 'kbd:0x1', 'kbd:1e0',
      'kbd:١', 'kbd:apv:abcde', 'kbd:perm:allow:abcde', 'kbd:kbd:0', 'kbd:99', 'kbd:100']
    const hostile: Btn[][] = [...forged.map(d => [{ text: 'Hostile ' + d, callback_data: d }]), ...kb('Alfa', 'Béta')]
    for (const data of forged) {
      for (const markup of [kb('Alfa', 'Béta'), hostile]) {
        const r = await h.press({ data, markup })
        expectToastOnly(h, r, DEAD, JSON.stringify(data))
      }
    }
  })

  it('AC-C3: forged data from a stranger is refused as a stranger, before the data is even looked at', async () => {
    const h = callbackHarness(patched)
    for (const data of ['kbd:12', 'kbd:x', 'kbd:']) {
      expectToastOnly(h, await h.press({ data, fromId: 99, chat: { id: 99, type: 'private' } }), NOT_ALLOWED, data)
    }
  })

  it('AC-C4: well-formed data that is not in the keyboard of the message the button sits on (index too high, no callback_data, empty keyboard, no reply_markup, InaccessibleMessage): toast only', async () => {
    const h = callbackHarness(patched)
    expectToastOnly(h, await h.press({ data: 'kbd:3', markup: kb('Alfa', 'Béta') }), DEAD, 'index beyond the keyboard')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[{ text: 'Link', url: 'https://example.invalid/' }]] }), DEAD, 'url button only')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [] }), DEAD, 'empty keyboard')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[]] }), DEAD, 'empty row')
    expectToastOnly(h, await h.press({ data: 'kbd:0', inaccessible: true }), DEAD, 'InaccessibleMessage')
    expectToastOnly(h, await h.press({ data: 'kbd:5', markup: [[{ text: 'Csak ez', callback_data: 'kbd:7' }]] }), DEAD, 'another index only')
  })

  it('B1: the label rule runs again on the label a tap brings back (slash, permission reply, control character): toast only, nothing delivered', async () => {
    const h = callbackHarness(patched)
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[{ text: '/context clear', callback_data: 'kbd:0' }]] }), DEAD, 'slash label')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[{ text: ' » /model opus', callback_data: 'kbd:0' }]] }), DEAD, 'slash after punctuation')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[{ text: 'yes abcde', callback_data: 'kbd:0' }]] }), DEAD, 'permission reply')
    expectToastOnly(h, await h.press({ data: 'kbd:0', markup: [[{ text: 'A\u0007B', callback_data: 'kbd:0' }]] }), DEAD, 'control character')
    expect(h.set.size).toBe(0)
  })

  it('AC-C9: the label comes from the button of the keyboard, never from the data; it is handed to handleInbound as (ctx, label, undefined) after the other buttons are taken off', async () => {
    const h = callbackHarness(patched)
    // kbd:1 is not the second label: rows with several buttons, other order, labels that look like data or a command
    const markup: Btn[][] = [
      [{ text: 'kbd:0', callback_data: 'kbd:2' }, { text: 'Ez a második gomb', callback_data: 'kbd:1' }],
      [{ text: 'A/B', callback_data: 'kbd:0' }],
    ]
    const r = await h.press({ data: 'kbd:1', markup })
    expect(r.edits).toEqual([{ reply_markup: { inline_keyboard: [[{ text: '✓ Ez a második gomb', callback_data: 'kbd:-' }]] } }])
    expect(r.answers).toEqual([{ text: '✓ Ez a második gomb' }])
    expect(h.delivered).toHaveLength(1)
    expect(h.delivered[0].text).toBe('Ez a második gomb')
    expect(h.delivered[0].text).not.toBe('kbd:1')
    expect(h.delivered[0].ctx).toBe(r.ctx)
    expect(h.delivered[0].img).toBeUndefined()
    expect(h.events).toEqual(['edit', 'answer', 'deliver'])
    expect([...h.set]).toEqual(['42:901'])
    expect(h.gateCalls).toHaveLength(0)
    expect(h.saveCalls).toHaveLength(0)
    // a label that is only data-shaped is still just the label of the button
    const r2 = await h.press({ data: 'kbd:2', markup, messageId: 902 })
    expect(h.delivered[1].text).toBe('kbd:0')
    expect(r2.answers).toEqual([{ text: '✓ kbd:0' }])
  })

  it('AC-C5: a second press on the same message (the second update still carries the old keyboard): one edit, one delivery, the second toast says it was answered', async () => {
    const h = callbackHarness(patched)
    const first = await h.press({ data: 'kbd:0' })
    const second = await h.press({ data: 'kbd:0' })
    const other = await h.press({ data: 'kbd:2' }) // another button of the same message, stale keyboard
    expect(first.answers).toEqual([{ text: '✓ Alfa' }])
    expect(second.answers).toEqual([{ text: ALREADY }])
    expect(other.answers).toEqual([{ text: ALREADY }])
    expect(first.edits).toHaveLength(1)
    expect(second.edits).toHaveLength(0)
    expect(other.edits).toHaveLength(0)
    expect(h.delivered.map(d => d.text)).toEqual(['Alfa'])
    expect([...h.set]).toEqual(['42:901'])
  })

  it('AC-C5: the Set is per message: another message, and another paired owner in his own chat, still deliver once each', async () => {
    const h = callbackHarness(patched, { allowFrom: ['42', '43'] })
    await h.press({ data: 'kbd:0', messageId: 901 })
    await h.press({ data: 'kbd:1', messageId: 902 })
    await h.press({ data: 'kbd:2', messageId: 901, fromId: 43, chat: { id: 43, type: 'private' } })
    expect(h.delivered.map(d => d.text)).toEqual(['Alfa', 'Béta', 'Gamma'])
    expect([...h.set].sort()).toEqual(['42:901', '42:902', '43:901'])
  })

  it('AC-C5: the Set is emptied before it grows past 1000 keys, and a tap still delivers', async () => {
    const full = callbackHarness(patched)
    for (let i = 0; i < 1000; i++) full.set.add(`1:${i}`)
    const r = await full.press({ data: 'kbd:0' })
    expect(r.answers).toEqual([{ text: '✓ Alfa' }])
    expect(full.delivered).toHaveLength(1)
    expect([...full.set]).toEqual(['42:901'])
    const almost = callbackHarness(patched)
    for (let i = 0; i < 999; i++) almost.set.add(`1:${i}`)
    await almost.press({ data: 'kbd:0' })
    expect(almost.set.size).toBe(1000)
    expect(almost.set.has('42:901')).toBe(true)
  })

  it('AC-C6: after a restart (new Set) a press on a message whose keyboard is already the "✓ label" / kbd:- button delivers nothing', async () => {
    const before = callbackHarness(patched)
    const r = await before.press({ data: 'kbd:1' })
    expect(r.edits).toHaveLength(1)
    expect(before.delivered).toHaveLength(1)
    // the plugin restarts: the Set is gone, the Telegram-side keyboard is the durable trace
    const after = callbackHarness(patched)
    const done: Btn[][] = [[{ text: '✓ Béta', callback_data: 'kbd:-' }]]
    expectToastOnly(after, await after.press({ data: 'kbd:-', markup: done }), ALREADY, 'kbd:- on the answered message')
    expectToastOnly(after, await after.press({ data: 'kbd:1', markup: done }), DEAD, 'old data on the answered message')
    expectToastOnly(after, await after.press({ data: 'kbd:0', markup: done }), DEAD, 'another old data on the answered message')
  })

  it('AC-C6: a kbd:- press (the answered button) is an answer to the tap only, in the same harness too', async () => {
    const h = callbackHarness(patched)
    const r = await h.press({ data: 'kbd:-', markup: [[{ text: '✓ Alfa', callback_data: 'kbd:-' }]] })
    expect(r.answers).toEqual([{ text: ALREADY }])
    expectToastOnly(h, r, ALREADY, 'kbd:-')
    // even if the keyboard is still the live one (forged or stale update): nothing to deliver
    expectToastOnly(h, await h.press({ data: 'kbd:-', markup: kb('Alfa', 'Béta') }), ALREADY, 'kbd:- on a live keyboard')
  })

  it('AC-C7: when the edit fails nothing is delivered, the key leaves the Set and the toast tells him to type; a repeated press with a working edit delivers once', async () => {
    const h = callbackHarness(patched)
    const bad = await h.press({ data: 'kbd:1', edit: 'fail' })
    expect(bad.answers).toEqual([{ text: NOT_RECORDED }])
    expect(bad.edits).toHaveLength(1)
    expect(h.delivered).toHaveLength(0)
    expect(h.set.size).toBe(0)
    expect(h.events).toEqual(['edit', 'answer'])
    expect(h.gateCalls).toHaveLength(0)
    const bad2 = await h.press({ data: 'kbd:1', edit: 'fail' })
    expect(bad2.answers).toEqual([{ text: NOT_RECORDED }])
    expect(h.delivered).toHaveLength(0)
    const good = await h.press({ data: 'kbd:1' })
    expect(good.answers).toEqual([{ text: '✓ Béta' }])
    expect(h.delivered.map(d => d.text)).toEqual(['Béta'])
    expect([...h.set]).toEqual(['42:901'])
    const again = await h.press({ data: 'kbd:1' })
    expect(again.answers).toEqual([{ text: ALREADY }])
    expect(h.delivered).toHaveLength(1)
  })

  it('AC-C8: every path calls answerCallbackQuery exactly once, also when it rejects; a failed toast neither blocks the delivery nor throws', async () => {
    const h = callbackHarness(patched, { allowFrom: ['42'] })
    const taps: TapSpec[] = [
      { data: 'kbd:0' }, // delivered
      { data: 'kbd:0' }, // already answered
      { data: 'kbd:1', messageId: 7, edit: 'fail' }, // edit failure
      { data: 'kbd:9' }, // not in the keyboard
      { data: 'kbd:12' }, // forged
      { data: 'kbd:-', markup: [[{ text: '✓ x', callback_data: 'kbd:-' }]] },
      { data: 'kbd:0', fromId: 99, chat: { id: 99, type: 'private' } }, // stranger
      { data: 'kbd:0', chat: { id: -100, type: 'supergroup' } }, // group
      { data: 'kbd:0', noMessage: true },
      { data: 'kbd:0', inaccessible: true },
    ]
    for (const t of taps) {
      const r = await h.press(t)
      expect(r.answers, JSON.stringify(t)).toHaveLength(1)
      expect(r.answers[0]?.text, JSON.stringify(t)).toEqual(expect.any(String))
    }
    // the toast request itself fails on a delivering path and on a refusing one
    const flaky = callbackHarness(patched)
    const ok = await flaky.press({ data: 'kbd:2', answerFails: true })
    expect(ok.answers).toHaveLength(1)
    expect(ok.edits).toHaveLength(1)
    expect(flaky.delivered.map(d => d.text)).toEqual(['Gamma'])
    const refused = await flaky.press({ data: 'kbd:2', fromId: 99, chat: { id: 99, type: 'private' }, answerFails: true })
    expect(refused.answers).toHaveLength(1)
    expect(flaky.delivered).toHaveLength(1)
    const editFail = await flaky.press({ data: 'kbd:1', messageId: 5, edit: 'fail', answerFails: true })
    expect(editFail.answers).toHaveLength(1)
    expect(flaky.delivered).toHaveLength(1)
    expect(flaky.set.has('42:5')).toBe(false)
  })

  it('AC-C10: data that is not kbd: keeps the old behaviour (perm branch, empty toast); kbd: lookalikes in case or with a prefix are not kbd', async () => {
    // The merged script also applies our apv patch, which takes `apv:` before the perm regex (covered by the apv suite and the
    // next test). This test is about a plugin WITHOUT an apv hook, where `apv:abc` is just another unknown press.
    const h = callbackHarness(patchedWithout(readFileSync(FIXTURE, 'utf-8'), 'apv'))
    // perm:allow by a paired user: the structured permission event, the old toast, the message text edited
    h.pendingPermissions.set('abcde', { tool_name: 'Bash', description: 'd', input_preview: '{}' })
    const allow = await h.press({ data: 'perm:allow:abcde' })
    expect(allow.answers).toEqual([{ text: '✅ Allowed' }])
    expect(h.permNotifications).toEqual([{ method: 'notifications/claude/channel/permission', params: { request_id: 'abcde', behavior: 'allow' } }])
    expect(h.pendingPermissions.has('abcde')).toBe(false)
    expect(allow.textEdits).toHaveLength(1)
    // perm from a stranger: refused by the plugin's own check
    const stranger = await h.press({ data: 'perm:deny:fghij', fromId: 99, chat: { id: 99, type: 'private' } })
    expect(stranger.answers).toEqual([{ text: 'Not authorized.' }])
    expect(h.permNotifications).toHaveLength(1)
    // perm:more with nothing pending
    const more = await h.press({ data: 'perm:more:mnopq' })
    expect(more.answers).toEqual([{ text: 'Details no longer available.' }])
    // everything else: the plugin's empty toast, once, and nothing else happens
    for (const data of ['xyz', '', 'KBD:0', ' kbd:0', 'xkbd:0', 'kbd', 'apv:abc']) {
      const r = await h.press({ data })
      expect(r.answers, JSON.stringify(data)).toEqual([undefined])
      expect(r.edits, JSON.stringify(data)).toHaveLength(0)
    }
    expect(h.delivered).toHaveLength(0)
    expect(h.set.size).toBe(0)
    expect(h.gateCalls).toHaveLength(0)
    expect(h.saveCalls).toHaveLength(0)
    // and a kbd: press afterwards is unaffected by all of that
    const tap = await h.press({ data: 'kbd:0' })
    expect(tap.answers).toEqual([{ text: '✓ Alfa' }])
    expect(h.delivered.map(d => d.text)).toEqual(['Alfa'])
  })

  it('AC-C10: with the apv hook line (PR #1964) in front of the perm regex, apv: still goes to that hook, and a kbd: press still works', async () => {
    const fixtureText = readFileSync(FIXTURE, 'utf-8')
    const withApv = fixtureText.replace(`${CALLBACK_OPEN}\n  const data = ctx.callbackQuery.data\n`, `${CALLBACK_OPEN}\n  const data = ctx.callbackQuery.data\n${APV_LINE}\n`)
    expect(withApv).not.toBe(fixtureText)
    writeFileSync(server, withApv)
    expect(run(['--topics', 'off']).status).toBe(0)
    const h = callbackHarness(readFileSync(server, 'utf-8'))
    const apv = await h.press({ data: 'apv:abc:allow' })
    expect(h.approvals).toEqual(['apv:abc:allow'])
    expect(apv.answers).toHaveLength(0) // the hook answers its own queries; the kbd branch and the plugin's empty toast never ran
    expect(h.delivered).toHaveLength(0)
    const tap = await h.press({ data: 'kbd:1' })
    expect(tap.answers).toEqual([{ text: '✓ Béta' }])
    expect(h.approvals).toHaveLength(1)
    expect(h.delivered.map(d => d.text)).toEqual(['Béta'])
  })

  it('AC-D1/D2: a tap through the real patched handleInbound: content is the label, meta has the question id and a fresh ts, no forwarded flag, the evidence record has message_id null', async () => {
    const inbound = inboundHarness(patched, stateDir)
    const h = callbackHarness(patched, { handleInbound: inbound.handleInbound })
    const r = await h.press({ data: 'kbd:1', messageId: 901 })
    expect(r.answers).toEqual([{ text: '✓ Béta' }])
    expect(inbound.notifications).toHaveLength(1)
    const n = inbound.notifications[0]
    expect(n.method).toBe('notifications/claude/channel')
    expect(n.params.content).toBe('Béta')
    expect(Object.keys(n.params.meta).sort()).toEqual(['chat_id', 'message_id', 'ts', 'user', 'user_id'])
    expect(n.params.meta).toMatchObject({ chat_id: '42', message_id: '901', user: 'owner', user_id: '42' })
    expect(n.params.meta).not.toHaveProperty('forwarded')
    expect(Number.isNaN(Date.parse(n.params.meta.ts))).toBe(false)
    expect(Math.abs(Date.now() - Date.parse(n.params.meta.ts))).toBeLessThan(5000)
    // the evidence line: the existing behaviour, message_id null (ctx.message is absent on a callback)
    const recs = inbound.evidence()
    expect(recs.map(e => [e.chat_id, e.message_id, e.text])).toEqual([['42', null, 'Béta']])
    // so the question id in the meta matches no evidence record, and a write command cannot ride on a tap
    const lines = readEvidenceLines(stateDir)
    expect(findEvidence(lines, '42', '901')).toBeNull()
    const verdict = (messageId: string | null, text: string) => checkWriteEvidence({ chatId: '42', messageId, text, now: Date.now() }, () => lines, () => true)
    expect(verdict(null, 'Béta')).toEqual({ ok: false, reason: 'no-message-id' })
    expect(verdict('901', 'Béta')).toEqual({ ok: false, reason: 'not-found' })
  })

  it('AC-D1: a typed message through the same patched handleInbound keeps its old meta exactly (ts from message.date, own message_id, nothing added)', async () => {
    const inbound = inboundHarness(patched, stateDir)
    const ctx: FakeCtx = {
      from: { id: 42, username: 'owner' },
      chat: { id: 42, type: 'private' },
      message: { message_id: 5, date: 1_700_000_000 },
    }
    await inbound.handleInbound(ctx, 'B', undefined)
    expect(inbound.notifications[0].params.content).toBe('B')
    expect(inbound.notifications[0].params.meta).toEqual({
      chat_id: '42', message_id: '5', user: 'owner', user_id: '42', ts: new Date(1_700_000_000 * 1000).toISOString(),
    })
    expect(inbound.evidence().map(e => [e.chat_id, e.message_id, e.text])).toEqual([['42', '5', 'B']])
  })

  it('AC-D1: a forwarded typed message is still flagged by the same patched handleInbound', async () => {
    const inbound = inboundHarness(patched, stateDir)
    await inbound.handleInbound({
      from: { id: 42 }, chat: { id: 42, type: 'private' },
      message: { message_id: 6, date: 1_700_000_000, forward_origin: { type: 'user' } },
    }, 'x', undefined)
    expect(inbound.notifications[0].params.meta.forwarded).toBe('1')
    expect(inbound.notifications[0].params.meta.user).toBe('42')
  })
})

// 345f34e2: the email-approval buttons. The repo module (an import-free TS file with its own tests) is copied in
// before the callback_query handler, between a BEGIN line carrying its sha256 and an END line, and one call line
// hands every apv: press to it before the perm: regex runs. The perm: branch stays byte for byte.
const APV = 'MARVEEN-PATCH(345f34e2-apv)'
const APV_SRC = join(ROOT, 'src', 'telegram-plugin-patches', 'approval-callback.ts')
const PERM_LINE = '  const m = /^perm:(allow|deny|more):([a-km-z]{5})$/.exec(data)\n'
const CALL_LINE = "  if (data.startsWith('apv:')) { await marveenApprovalCallback(ctx, data, { stateDir: STATE_DIR, readFileSync, fetch, loadAccess, env: process.env, envAtLoad: MARVEEN_APV_ENV_AT_LOAD }); return } // MARVEEN-PATCH(345f34e2-apv)\n"
// The env as the plugin loaded it: bun keeps proxying after a runtime delete from process.env (BE-2, 2nd round).
const SNAP_LINE = 'const MARVEEN_APV_ENV_AT_LOAD = { ...process.env } // MARVEEN-PATCH(345f34e2-apv)\n'

// The fixture patched by the script without the named patches.
function patchedWithout(text: string, ...names: string[]): string {
  const code = [
    'import importlib.util, json, sys',
    "spec = importlib.util.spec_from_file_location('ptp', sys.argv[1])",
    'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
    "skip = json.loads(sys.argv[2])",
    "m.PATCHES = [p for p in m.PATCHES if p['name'] not in skip]",
    'sys.stdout.write(m.patch_text(sys.stdin.read())[0])',
  ].join('\n')
  const r = spawnSync('python3', ['-c', code, SCRIPT, JSON.stringify(names)], { input: text, encoding: 'utf-8' })
  expect(r.status).toBe(0)
  return r.stdout
}

// The callback_query handler, from its opening line to its closing `})` at column 0.
function callbackHandler(text: string): string {
  const m = /^bot\.on\('callback_query:data', async ctx => \{\n[\s\S]*?^\}\)\n/m.exec(text)
  expect(m).not.toBeNull()
  return m![0]
}

function sha16(file: string): string {
  return createHash('sha256').update(readFileSync(file)).digest('hex').slice(0, 16)
}

// A scratch install: the script beside its own src/ tree, so the module source can be varied
// (the script reads <install>/src/telegram-plugin-patches/approval-callback.ts).
function scratchInstall(source: string | null): string {
  const inst = join(cache, 'install')
  mkdirSync(join(inst, 'scripts'), { recursive: true })
  copyFileSync(SCRIPT, join(inst, 'scripts', 'patch-telegram-plugin.py'))
  mkdirSync(join(inst, 'src', 'telegram-plugin-patches'), { recursive: true })
  const src = join(inst, 'src', 'telegram-plugin-patches', 'approval-callback.ts')
  rmSync(src, { force: true })
  if (source !== null) writeFileSync(src, source)
  return join(inst, 'scripts', 'patch-telegram-plugin.py')
}

function runWith(script: string, extra: string[] = []): { status: number | null; stderr: string } {
  const r = spawnSync('python3', [script, ...extra, cache], { encoding: 'utf-8', timeout: 30_000 })
  return { status: r.status, stderr: r.stderr }
}

type CbCall = [string, ...unknown[]]

// Runs the PATCHED block + callback_query handler with a fake bot: which branch a press takes, and what it calls.
function callbackRunner(patched: string, allowFrom: string[], stateDir: string, env: Record<string, string> = {}) {
  const start = patched.indexOf(`// ${APV} BEGIN`)
  expect(start).toBeGreaterThan(0)
  const handler = callbackHandler(patched)
  const end = patched.indexOf(handler) + handler.length
  const js = ts.transpileModule(patched.slice(start, end), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  let registered: ((ctx: unknown) => Promise<void>) | undefined
  const bot = { on: (ev: string, fn: (ctx: unknown) => Promise<void>) => { expect(ev).toBe('callback_query:data'); registered = fn } }
  const notes: unknown[] = []
  const fetches: Array<[string, RequestInit]> = []
  const fakeFetch = async (url: string, init: RequestInit) => {
    fetches.push([url, init])
    const status = JSON.parse(String(init.body)).status
    return new Response(JSON.stringify({ ok: true, approval: { status }, outcome_text: 'OK' }), { status: 200 })
  }
  // `process` is the plugin's: a fake one with no proxy variable, so the runner's own env cannot leak in
  const names = ['bot', 'STATE_DIR', 'readFileSync', 'fetch', 'loadAccess', 'mcp', 'pendingPermissions', 'InlineKeyboard', 'process']
  new Function(...names, js)(bot, stateDir, readFileSync, fakeFetch, () => ({ allowFrom }),
    { notification: (n: unknown) => { notes.push(n); return Promise.resolve() } }, new Map(), class {}, { env })
  expect(registered).toBeDefined()
  const press = async (data: string, from = 42) => {
    const calls: CbCall[] = []
    const ctx = {
      from: { id: from },
      callbackQuery: { data, message: { message_id: 77, chat: { id: from, type: 'private' }, text: 'Jóváhagyás' } },
      answerCallbackQuery: async (...a: unknown[]) => { calls.push(['answerCallbackQuery', ...a]) },
      editMessageText: async (...a: unknown[]) => { calls.push(['editMessageText', ...a]) },
      editMessageReplyMarkup: async (...a: unknown[]) => { calls.push(['editMessageReplyMarkup', ...a]) },
    }
    await registered!(ctx)
    return calls
  }
  return { press, notes, fetches }
}

describe('apv: email-approval buttons (345f34e2)', () => {
  it('1st run: one marked block before the handler, the call line right before the perm: regex, the file parses', () => {
    const state = join(cache, 'state.json')
    expect(run(['--state', state]).status).toBe(0)
    const text = readFileSync(server, 'utf-8')
    expect(readState(state).files[0].patches.apv).toBe('patched')
    expect(text.split(APV)).toHaveLength(5)
    expect(text).toContain(`// ${APV} BEGIN src-sha256:${sha16(APV_SRC)}\n`)
    expect(text).toContain(`// ${APV} END\n${SNAP_LINE}bot.on('callback_query:data', async ctx => {\n  const data = ctx.callbackQuery.data\n${CALL_LINE}${PERM_LINE}`)
    const begin = text.indexOf(`// ${APV} BEGIN`)
    const block = text.slice(text.indexOf('\n', begin) + 1, text.indexOf(`// ${APV} END`))
    // the module verbatim, only its line-leading `export ` cut
    expect(block).toBe(readFileSync(APV_SRC, 'utf-8').replace(/^export /gm, ''))
    expect(block).not.toMatch(/^export /m)
    expect(block).not.toMatch(/\bimport\b|\bmcp\b|notification/)
    expect(syntaxErrors(text)).toEqual([])
  })

  it('the perm: branch is byte-identical, and taking the patch back (BEGIN..END, snapshot and call line) gives the file patched without it', () => {
    run()
    const text = readFileSync(server, 'utf-8')
    // v1.45.0 merge (c3c32903, test setup): the kbd patch now has lines inside the handler, so "byte-identical" is
    // measured against the handler of the file patched without apv, not the raw fixture.
    expect(callbackHandler(text).replace(CALL_LINE, '')).toBe(callbackHandler(patchedWithout(readFileSync(FIXTURE, 'utf-8'), 'apv')))
    const back = text.replace(/^\/\/ MARVEEN-PATCH\(345f34e2-apv\) BEGIN[^\n]*\n[\s\S]*?^\/\/ MARVEEN-PATCH\(345f34e2-apv\) END\n/m, '').replace(SNAP_LINE, '').replace(CALL_LINE, '')
    expect(back).not.toContain(APV)
    expect(back).toBe(patchedWithout(readFileSync(FIXTURE, 'utf-8'), 'apv'))
  })

  it('the patched handler: apv: goes to the block (one POST to the Telegram endpoint, no model notification), perm: and anything else as before', async () => {
    run()
    const inst = mkdtempSync(join(tmpdir(), 'tg-apv-inst-'))
    try {
      const stateDir = join(inst, '.claude', 'channels', 'telegram')
      mkdirSync(stateDir, { recursive: true })
      mkdirSync(join(inst, 'store'))
      writeFileSync(join(inst, 'store', '.dashboard-token'), 'test-token\n')
      const p = callbackRunner(readFileSync(server, 'utf-8'), ['42'], stateDir)
      const id32 = '0123456789abcdef0123456789abcdef'
      const nonce = 'AAAAAAAAAAAAAAAAAAAAAA'
      const ok = await p.press(`apv:a:${id32}:${nonce}`)
      expect(p.fetches).toHaveLength(1)
      expect(p.fetches[0][0]).toBe('http://127.0.0.1:3420/api/approvals/01234567-89ab-cdef-0123-456789abcdef/telegram')
      expect(p.fetches[0][1].method).toBe('POST')
      expect(JSON.parse(String(p.fetches[0][1].body))).toMatchObject({ status: 'approved', resolved_by: 'owner:telegram:42', telegram_message_id: 77, callback_nonce: nonce })
      expect(ok.at(-1)).toEqual(['answerCallbackQuery', { text: '✅ Jóváhagyva.' }])
      // a stranger's press: refused in the block, no request, and still not the perm: branch
      expect(await p.press(`apv:r:${id32}:${nonce}`, 99)).toEqual([['answerCallbackQuery', { text: 'Nem engedélyezett.' }]])
      // a malformed apv: press is answered by the block, never by the perm: branch
      expect(await p.press('apv:a:nope')).toEqual([['answerCallbackQuery', { text: 'Érvénytelen gomb.' }]])
      expect(p.fetches).toHaveLength(1)
      expect(p.notes).toEqual([])
      // perm: exactly as before: the model is notified, no HTTP
      expect(await p.press('perm:allow:abcde')).toEqual([['answerCallbackQuery', { text: '✅ Allowed' }], ['editMessageText', 'Jóváhagyás\n\n✅ Allowed']])
      expect(p.notes).toEqual([{ method: 'notifications/claude/channel/permission', params: { request_id: 'abcde', behavior: 'allow' } }])
      // anything else: the plugin's silent acknowledgement
      expect(await p.press('something-else')).toEqual([['answerCallbackQuery']])
      expect(p.fetches).toHaveLength(1)
    } finally { rmSync(inst, { recursive: true, force: true }) }
  })

  it('the patched handler passes the plugin env: with HTTP_PROXY set an apv: press sends nothing (BE-2)', async () => {
    run()
    const inst = mkdtempSync(join(tmpdir(), 'tg-apv-inst-'))
    try {
      const stateDir = join(inst, '.claude', 'channels', 'telegram')
      mkdirSync(stateDir, { recursive: true })
      mkdirSync(join(inst, 'store'))
      writeFileSync(join(inst, 'store', '.dashboard-token'), 'test-token\n')
      const data = `apv:a:${'0123456789abcdef'.repeat(2)}:${'A'.repeat(22)}`
      const refused = [['answerCallbackQuery', { text: 'A gomb most nem működik, dönts a dashboardon.' }]]
      const p = callbackRunner(readFileSync(server, 'utf-8'), ['42'], stateDir, { HTTP_PROXY: 'http://proxy.test:8080' })
      expect(await p.press(data)).toEqual(refused)
      expect(p.fetches).toEqual([])
      // set at load, deleted later: the snapshot still has it (bun would still proxy)
      const loadEnv: Record<string, string> = { HTTP_PROXY: 'http://proxy.test:8080' }
      const q = callbackRunner(readFileSync(server, 'utf-8'), ['42'], stateDir, loadEnv)
      delete loadEnv.HTTP_PROXY
      expect(await q.press(data)).toEqual(refused)
      expect(q.fetches).toEqual([])
      // clean at load, set later: the current env has it
      const runEnv: Record<string, string> = {}
      const r = callbackRunner(readFileSync(server, 'utf-8'), ['42'], stateDir, runEnv)
      runEnv.http_proxy = 'http://proxy.test:8080'
      expect(await r.press(data)).toEqual(refused)
      expect(r.fetches).toEqual([])
      // clean at load and now: the request goes out
      const ok = callbackRunner(readFileSync(server, 'utf-8'), ['42'], stateDir, {})
      expect((await ok.press(data)).at(-1)).toEqual(['answerCallbackQuery', { text: '✅ Jóváhagyva.' }])
      expect(ok.fetches).toHaveLength(1)
    } finally { rmSync(inst, { recursive: true, force: true }) }
  })

  it('2nd run is a byte-identical no-op', () => {
    run()
    const once = readFileSync(server, 'utf-8')
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.stderr).toBe('')
    expect(readFileSync(server, 'utf-8')).toBe(once)
    expect(readState(state).files[0].patches.apv).toBe('already')
  })

  it.each([
    ['perm regex', (t: string) => t.replace('const m = /^perm:(allow|deny|more):([a-km-z]{5})$/.exec(data)', 'const m = /^perm:(allow|deny|more|info):([a-km-z]{5})$/.exec(data)')],
    ['callback_query handler', (t: string) => t.replace("bot.on('callback_query:data', async ctx => {", "bot.on('callback_query:data', async (ctx) => {")],
    ['callback_query handler', (t: string) => `${t}\nbot.on('callback_query:data', async ctx => {\n})\n`],
    ['callback data line', (t: string) => t.replace('  const data = ctx.callbackQuery.data\n', '  const data = ctx.callbackQuery.data\n  const extra = 1\n')],
    ['fs readFileSync import', (t: string) => t.replace("import { readFileSync, writeFileSync,", "import { writeFileSync,")],
    ['STATE_DIR', (t: string) => t.replace('const STATE_DIR = ', 'const STATE_DIRECTORY = ')],
    ['loadAccess', (t: string) => t.replace('function loadAccess()', 'function loadAccessFile()')],
  ])('a moved or doubled anchor (%s): loud line, apv left out whole, the other patches still applied', (name, change) => {
    writeFileSync(server, change(readFileSync(FIXTURE, 'utf-8')))
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toContain(`LOUD: ${name} not found exactly once`)
    expect(r.stderr).toMatch(/the apv patch left out, the email-approval buttons do nothing/)
    const text = readFileSync(server, 'utf-8')
    expect(text).not.toContain(APV)
    expect(text).not.toContain('marveenApprovalCallback')
    expect(readState(state).files[0].patches).toEqual({ d4: 'patched', fwd: 'patched', evid: 'patched', kbd: 'patched', apv: `anchor-missing:${name}` })
  })

  it('a plugin that already has one of the block\'s names: nothing inserted, loudly', () => {
    writeFileSync(server, readFileSync(FIXTURE, 'utf-8') + '\nconst MARVEEN_APV_TOAST = 1\n')
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.stderr).toMatch(/LOUD: conflict:apv names in .*the apv patch not applied/)
    expect(readFileSync(server, 'utf-8')).not.toContain(APV)
    expect(readState(state).files[0].patches.apv).toBe('conflict:apv names')
  })

  it('a changed module source replaces the old block: one block, the new sha, one call line; then a no-op', () => {
    run()
    const changed = readFileSync(APV_SRC, 'utf-8') + '\n// a later revision\n'
    const script = scratchInstall(changed)
    const state = join(cache, 'state.json')
    const r = runWith(script, ['--state', state])
    expect(r.stderr).toMatch(/patched .*\(apv\)/)
    const text = readFileSync(server, 'utf-8')
    expect(text.split(APV)).toHaveLength(5)
    expect(text).toContain(`BEGIN src-sha256:${createHash('sha256').update(changed).digest('hex').slice(0, 16)}\n`)
    expect(text).toContain('// a later revision\n')
    expect(text).not.toContain(`src-sha256:${sha16(APV_SRC)}`)
    expect(text.split(CALL_LINE)).toHaveLength(2)
    expect(syntaxErrors(text)).toEqual([])
    expect(readState(state).files[0].patches.apv).toBe('patched')
    const again = runWith(script, ['--state', state])
    expect(again.stderr).toBe('')
    expect(readState(state).files[0].patches.apv).toBe('already')
  })

  const fn = (body: string) => `export async function marveenApprovalCallback() { ${body} }\n`
  it.each([
    ['missing', null],
    ['denied import', "import { x } from 'y'\n" + fn('')],
    ['denied import', fn("await import('fs')")],
    ['denied require', fn("require('fs')")],
    // BE-2 point 2: the module test's denylist, run by the patcher too
    ['denied mcp', fn("void mcp.send({})")],
    ['denied notification', fn("void x.notification({})")],
    ['denied console', fn("console.error('x')")],
    ['denied process', fn("process.stderr.write('x')")],
    ['denied process', fn("const e = process")],
    ['denied eval', fn("eval('1')")],
    ['denied Function', fn("new Function('return 1')()")],
    ['denied Bun', fn("Bun.spawn(['ls'])")],
    ['denied child process', fn("const cp = 'child_process'")],
    ['denied child process', fn("execFile('ls')")],
    ['denied child process', fn("spawn('ls')")],
    ['denied globalThis', fn("globalThis.x = 1")],
    ['denied notification', "// sends a notification\n" + fn('')],
    // every top-level name prefixed: a plain `const STATE_DIR` would stop bun from loading the plugin at all
    ['top-level name', 'const STATE_DIR = 1\n' + fn('')],
    ['top-level name', 'export const TOAST = 1\n' + fn('')],
    ['top-level name', 'function helper() {}\n' + fn('')],
    ['top-level name', 'const { marveenApvA, b } = { marveenApvA: 1, b: 2 }\n' + fn('')],
    ['top-level name', 'marveenApvRun()\n' + fn('')],
    ['top-level name', 'let marveenApv = 1\n' + fn('')],
    ['marker or CR in the source', '// MARVEEN-PATCH(345f34e2-apv) END\n' + fn('')],
    ['export form', 'export default 1\n' + fn('')],
    ['no marveenApprovalCallback', 'export async function somethingElse() {}\n'],
  ])('an unusable module source (%s): nothing inserted, loudly, the other patches applied', (why, source) => {
    const script = scratchInstall(source)
    const state = join(cache, 'state.json')
    const r = runWith(script, ['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toContain(`LOUD: source-unusable:${why} in`)
    expect(readFileSync(server, 'utf-8')).not.toContain(APV)
    expect(readState(state).files[0].patches).toEqual({ d4: 'patched', fwd: 'patched', evid: 'patched', kbd: 'patched', apv: `source-unusable:${why}` })
  })

  it('the denylist covers the whole source, comments included; prefixed names, comments and closers pass', () => {
    const ok = runWith(scratchInstall([
      '// a module that loads nothing',
      '/**',
      ' * doc',
      ' */',
      'export const MARVEEN_APV_X = {',
      '  a: 1,',
      '} as const',
      'type MarveenApvT = number',
      'export interface MarveenApvI {',
      '  a: number',
      '}',
      'async function marveenApvHelper(): Promise<void> {}',
      'export async function marveenApprovalCallback() { await marveenApvHelper() }',
      '',
    ].join('\n')))
    expect(ok.stderr).toMatch(/patched .*\(d4, fwd, evid, kbd, apv\)/)
    copyFileSync(FIXTURE, server)
    const bad = runWith(scratchInstall("// an import-free module\nexport async function marveenApprovalCallback() {}\n"))
    expect(bad.stderr).toContain('LOUD: source-unusable:denied import in')
    expect(readFileSync(server, 'utf-8')).not.toContain(APV)
  })

  it('the real module source passes every source check', () => {
    const r = spawnSync('python3', ['-c', [
      'import importlib.util, sys',
      "spec = importlib.util.spec_from_file_location('ptp', sys.argv[1])",
      'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
      'block, sha = m.apv_source()',
      "print('ok' if block else 'unusable:' + sha)",
    ].join('\n'), SCRIPT], { encoding: 'utf-8' })
    expect(r.stdout.trim()).toBe('ok')
  })

  // BE-2 point 3: a matching sha label is not enough -- the block and the call line are compared with what the
  // source gives now, and a hand edit is replaced (loudly), then the next run is a no-op again.
  it.each<[string, (t: string) => string]>([
    ['the block', t => t.replace("redirect: 'manual'", "redirect: 'follow'")],
    ['the call line', t => t.replace('env: process.env, envAtLoad', 'env: {}, envAtLoad')],
    ['the snapshot line', t => t.replace('MARVEEN_APV_ENV_AT_LOAD = { ...process.env } //', 'MARVEEN_APV_ENV_AT_LOAD = {} //')],
    ['the snapshot line (removed)', t => t.replace(SNAP_LINE, '')],
    ['a line added inside the block', t => t.replace(`// ${APV} END\n`, `const injected = 1\n// ${APV} END\n`)],
  ])('a hand edit of %s under the matching label is replaced, loudly', (_name, edit) => {
    run()
    const clean = readFileSync(server, 'utf-8')
    const edited = edit(clean)
    expect(edited).not.toBe(clean)
    writeFileSync(server, edited)
    const state = join(cache, 'state.json')
    const r = run(['--state', state])
    expect(r.status).toBe(0)
    expect(r.stderr).toMatch(/LOUD: the apv block or a marked apv line differs from its source under a matching label/)
    expect(readFileSync(server, 'utf-8')).toBe(clean)
    expect(readState(state).files[0].patches.apv).toBe('patched')
    const again = run(['--state', state])
    expect(again.stderr).toBe('')
    expect(readState(state).files[0].patches.apv).toBe('already')
  })

  it('the module source gone later: the block in place is kept (not refreshed), loudly', () => {
    run()
    const once = readFileSync(server, 'utf-8')
    const state = join(cache, 'state.json')
    const r = runWith(scratchInstall(null), ['--state', state])
    expect(r.stderr).toMatch(/LOUD: source-unusable:missing in .*not applied or not refreshed/)
    expect(readFileSync(server, 'utf-8')).toBe(once)
    expect(readState(state).files[0].patches.apv).toBe('source-unusable:missing')
  })

  it.each([
    ['END line gone', (t: string) => t.replace(`// ${APV} END\n`, '')],
    ['call line gone', (t: string) => t.replace(CALL_LINE, '')],
    ['snapshot line doubled', (t: string) => t.replace(SNAP_LINE, SNAP_LINE + SNAP_LINE)],
    ['snapshot line inside the block', (t: string) => t.replace(SNAP_LINE, '').replace(`// ${APV} END\n`, `${SNAP_LINE}// ${APV} END\n`)],
    ['block doubled', (t: string) => t.replace(/^\/\/ MARVEEN-PATCH\(345f34e2-apv\) BEGIN[^\n]*\n[\s\S]*?^\/\/ MARVEEN-PATCH\(345f34e2-apv\) END\n/m, b => b + b)],
  ])('damaged markers (%s): the file is not touched, loudly', (_name, damage) => {
    run()
    const damaged = damage(readFileSync(server, 'utf-8'))
    writeFileSync(server, damaged)
    const state = join(cache, 'state.json')
    const r = runWith(scratchInstall(readFileSync(APV_SRC, 'utf-8') + '\n// newer\n'), ['--state', state])
    expect(r.stderr).toMatch(/LOUD: damaged:apv markers in /)
    expect(readFileSync(server, 'utf-8')).toBe(damaged)
    expect(readState(state).files[0]).toMatchObject({ status: 'damaged:apv markers', patches: { apv: 'damaged:apv markers' } })
  })
})

describe('channels.sh wiring (review #1529, point 1)', () => {
  const sh = readFileSync(join(ROOT, 'scripts', 'channels.sh'), 'utf-8')
  const code = sh.split('\n').filter(l => !l.trim().startsWith('#')).join('\n')

  it('calls the patcher for Telegram, with the state file, before the session (and so the plugin) is spawned', () => {
    const call = code.indexOf('scripts/patch-telegram-plugin.py" --state "$INSTALL_DIR/store/telegram-plugin-patch.json"')
    const spawn = code.indexOf('$TMUX new-session -d -s "$SESSION"')
    expect(call).toBeGreaterThan(0)
    expect(spawn).toBeGreaterThan(call)
    // guarded by the Telegram provider check, directly: no other block in between
    const cond = code.lastIndexOf('if [ "$CHANNEL_PROVIDER" = "telegram" ]; then', call)
    expect(cond).toBeGreaterThan(0)
    expect(code.slice(cond, call).split('\n').length).toBeLessThanOrEqual(3)
    // both branches (own config dir / inherited one) write the state file
    expect(code.split('scripts/patch-telegram-plugin.py" --state "$INSTALL_DIR/store/telegram-plugin-patch.json"').length - 1).toBe(2)
  })

  it('an isolated/explicit config dir is handed to the patcher, so it writes the cache the session launches from', () => {
    expect(code).toMatch(/if \[ -n "\$CFG_ENV" \]; then\n\s*CLAUDE_CONFIG_DIR="\$_cfg_dir" python3 "\$INSTALL_DIR\/scripts\/patch-telegram-plugin\.py"/)
  })
})

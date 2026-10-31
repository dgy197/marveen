// Fake Telegram Bot API on 127.0.0.1 for the permission-bot relay tests (card d7f586bf).
//
// Serves /bot<token>/<method> with the Bot-API envelope, records every call,
// and keeps an update queue with real offset semantics (getUpdates with offset
// N confirms and forgets every update_id < N; long-poll waits up to `timeout`
// seconds for a push). Modes switch getUpdates into failure behaviour:
//   conflict          409 "terminated by other getUpdates request"
//   webhook_conflict  409 "can't use getUpdates method while webhook is active"
//   error5xx          502 with a non-JSON body
//   unauthorized      401
//   fatal_echo        400 whose description echoes the request path (token included)
//   hang              never answers (until close)
// A wrong token always gets 401. No outbound connection is ever made.

import http from 'node:http'
import type { AddressInfo, Socket } from 'node:net'

export type FakeMode = 'normal' | 'conflict' | 'webhook_conflict' | 'error5xx' | 'unauthorized' | 'fatal_echo' | 'hang' | 'rate429'

export interface FakeCall {
  method: string
  body: Record<string, unknown>
  tokenOk: boolean
}

export class FakeBotApi {
  readonly calls: FakeCall[] = []
  mode: FakeMode = 'normal'
  // How many getUpdates calls the mode applies to; then back to 'normal'. null = forever.
  modeCalls: number | null = null
  // Per-call script: each getUpdates takes the next entry; when empty, `mode` applies.
  script: FakeMode[] = []
  webhookUrl = ''
  botId: number
  private queue: Array<Record<string, unknown> & { update_id: number }> = []
  private nextId = 1000
  private waiters: Array<() => void> = []
  private server: http.Server | null = null
  private sockets = new Set<Socket>()
  url = ''

  constructor(private readonly token: string) {
    this.botId = Number(token.split(':')[0])
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => { void this.onRequest(req, res) })
    this.server.on('connection', (s) => { this.sockets.add(s); s.on('close', () => this.sockets.delete(s)) })
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve))
    const addr = this.server.address() as AddressInfo
    this.url = `http://127.0.0.1:${addr.port}`
  }

  async close(): Promise<void> {
    for (const w of this.waiters.splice(0)) w()
    for (const s of this.sockets) s.destroy()
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()))
    this.server = null
  }

  // Queue an update; returns its update_id.
  push(update: Record<string, unknown>): number {
    const id = this.nextId++
    this.queue.push({ ...update, update_id: id })
    for (const w of this.waiters.splice(0)) w()
    return id
  }

  pushCallback(data: string, extra: Record<string, unknown> = {}): number {
    return this.push({
      callback_query: {
        id: `cbq-${this.nextId}`,
        from: { id: 11, is_bot: false },
        message: { message_id: 7, chat: { id: 11, type: 'private' }, from: { id: this.botId, is_bot: true } },
        data,
        ...extra,
      },
    })
  }

  pending(): number[] {
    return this.queue.map((u) => u.update_id)
  }

  callsOf(method: string): FakeCall[] {
    return this.calls.filter((c) => c.method === method)
  }

  private async onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown> } catch { body = {} }
    const m = /^\/bot([^/]+)\/([A-Za-z]+)$/.exec(req.url ?? '')
    const method = m?.[2] ?? 'unknown'
    const tokenOk = !!m && decodeURIComponent(m[1]!) === this.token
    this.calls.push({ method, body, tokenOk })
    const send = (status: number, payload: unknown, raw = false): void => {
      if (res.writableEnded) return
      res.writeHead(status, { 'content-type': raw ? 'text/html' : 'application/json' })
      res.end(raw ? String(payload) : JSON.stringify(payload))
    }
    if (!tokenOk) return send(401, { ok: false, error_code: 401, description: 'Unauthorized' })

    switch (method) {
      case 'getMe':
        return send(200, { ok: true, result: { id: this.botId, is_bot: true, username: 'fake_permission_bot' } })
      case 'getWebhookInfo':
        return send(200, { ok: true, result: { url: this.webhookUrl, pending_update_count: this.queue.length } })
      case 'deleteWebhook':
        this.webhookUrl = ''
        return send(200, { ok: true, result: true })
      case 'answerCallbackQuery':
        return send(200, { ok: true, result: true })
      case 'getUpdates':
        return this.getUpdates(req, res, body, send)
      default:
        return send(404, { ok: false, error_code: 404, description: 'Not Found' })
    }
  }

  private async getUpdates(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    body: Record<string, unknown>,
    send: (status: number, payload: unknown, raw?: boolean) => void,
  ): Promise<void> {
    const scripted = this.script.shift()
    const mode = scripted ?? this.mode
    if (scripted === undefined && mode !== 'normal' && this.modeCalls !== null) {
      this.modeCalls--
      if (this.modeCalls <= 0) { this.mode = 'normal'; this.modeCalls = null }
    }
    switch (mode) {
      case 'conflict':
        return send(409, { ok: false, error_code: 409, description: 'Conflict: terminated by other getUpdates request; make sure that only one bot instance is running' })
      case 'webhook_conflict':
        return send(409, { ok: false, error_code: 409, description: "Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first" })
      case 'error5xx':
        return send(502, `<html>Bad gateway for ${req.url}</html>`, true)
      case 'unauthorized':
        return send(401, { ok: false, error_code: 401, description: 'Unauthorized' })
      case 'fatal_echo':
        return send(400, { ok: false, error_code: 400, description: `Bad Request: unexpected path ${req.url}` })
      case 'hang':
        return
      case 'rate429':
        return send(429, { ok: false, error_code: 429, description: 'Too Many Requests: retry after 1', parameters: { retry_after: 1 } })
      default:
        break
    }
    const offset = typeof body['offset'] === 'number' ? body['offset'] : undefined
    if (offset !== undefined && offset > 0) this.queue = this.queue.filter((u) => u.update_id >= offset)
    const limit = typeof body['limit'] === 'number' ? body['limit'] : 100
    const timeoutSec = typeof body['timeout'] === 'number' ? body['timeout'] : 0
    if (this.queue.length === 0 && timeoutSec > 0) {
      await new Promise<void>((resolve) => {
        const t = setTimeout(done, timeoutSec * 1000)
        function done(): void { clearTimeout(t); resolve() }
        this.waiters.push(done)
        // res, not req: req 'close' fires once the body has been read.
        res.on('close', done)
      })
    }
    send(200, { ok: true, result: this.queue.slice(0, limit) })
  }
}

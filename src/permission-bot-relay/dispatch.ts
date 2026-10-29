// Prefix dispatcher of the permission-bot relay (card d7f586bf, spec F3.6).
//
// callback_data starts with a three-letter lowercase prefix and a colon
// ("apv:"). The table maps an exact prefix to its handler; anything else -- an
// unknown prefix ("ppr:" until its handler is wired here, card 5a5b82a0), an
// upper-case or space-led variant, no data at all -- gets the generic "not
// valid" toast and is never forwarded. The match is exact: no trim, no case
// fold. Only the handler of the matching prefix sees the update.
//
// Nothing about the data is logged: not the data, not even the prefix.

import { answerToast, TOAST_INVALID } from './apv-handler.js'
import type { HandlerOutcome, RelayLog, UpdateHandler } from './poll-loop.js'

const PREFIX_KEY_RE = /^[a-z]{3}:$/
const DATA_PREFIX_RE = /^([a-z]{3}:)/

export function createDispatcher(table: Record<string, UpdateHandler>, opts: { log: RelayLog }): UpdateHandler {
  const handlers = new Map<string, UpdateHandler>()
  for (const [prefix, handler] of Object.entries(table)) {
    if (!PREFIX_KEY_RE.test(prefix)) throw new TypeError('dispatcher: a prefix must be three lowercase letters and a colon')
    if (typeof handler !== 'function') throw new TypeError('dispatcher: handler is not a function')
    handlers.set(prefix, handler)
  }
  const { log } = opts

  return async (update, ctx): Promise<HandlerOutcome> => {
    const cbq = update.callback_query
    if (!cbq || typeof cbq !== 'object') return 'rejected'
    const m = typeof cbq.data === 'string' ? DATA_PREFIX_RE.exec(cbq.data) : null
    const handler = m ? handlers.get(m[1]!) : undefined
    if (!handler) {
      log.warn({ update_id: update.update_id, reason: 'unknown_prefix' }, 'permission-bot-relay: callback with no handler, not forwarded')
      await answerToast(ctx.api, cbq, TOAST_INVALID, log, update.update_id, ctx.signal)
      return 'rejected'
    }
    return handler(update, ctx)
  }
}

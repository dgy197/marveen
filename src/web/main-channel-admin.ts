import { MAIN_CHANNEL_ADMIN_ENV, isAdminSwitchOn } from './admin-switch.js'

// Card 053f4e66 (Brainy 1954): every dashboard route that writes the MAIN
// agent's channel state -- its access.json (allowFrom, dmPolicy, groups,
// channels), its pairing state (pending, invites.json, approved/) or its
// channel .env -- is refused with 403 unless the install's .env has
// MAIN_CHANNEL_ADMIN_ENABLED=1. The shared Bearer is held by every agent of the
// fleet; with these routes open it could pair a stranger to the owner's bot.
// Sub-agents' own bots are untouched. The plugin's terminal-side
// /telegram:access skill edits the files directly and is not affected.
export { MAIN_CHANNEL_ADMIN_ENV }

export function isMainChannelAdminEnabled(): boolean {
  return isAdminSwitchOn(MAIN_CHANNEL_ADMIN_ENV)
}

const P = '(telegram|slack|discord|googlechat|teams)'

// [method, pattern, action]. Group 1 is always the agent name. The patterns
// mirror the handlers in routes/agents.ts (new /channels/<p>/ and legacy
// /telegram/ forms), and are deliberately a little wider (every provider) so a
// handler that later grows a provider cannot slip out of the gate.
const MAIN_CHANNEL_WRITES: ReadonlyArray<[string, RegExp, string]> = [
  ['POST', new RegExp(`^/api/agents/([^/]+)/channels/${P}$`), 'channel-setup'],
  ['POST', /^\/api\/agents\/([^/]+)\/telegram$/, 'channel-setup'],
  ['DELETE', new RegExp(`^/api/agents/([^/]+)/channels/${P}$`), 'channel-remove'],
  ['DELETE', /^\/api\/agents\/([^/]+)\/telegram$/, 'channel-remove'],
  ['POST', new RegExp(`^/api/agents/([^/]+)/channels/${P}/approve$`), 'pairing-approve'],
  ['POST', /^\/api\/agents\/([^/]+)\/telegram\/approve$/, 'pairing-approve'],
  ['POST', new RegExp(`^/api/agents/([^/]+)/channels/${P}/invites$`), 'invite-create'],
  ['POST', /^\/api\/agents\/([^/]+)\/telegram\/invites$/, 'invite-create'],
  ['DELETE', new RegExp(`^/api/agents/([^/]+)/channels/${P}/invites/.+$`), 'invite-revoke'],
  ['DELETE', /^\/api\/agents\/([^/]+)\/telegram\/invites\/.+$/, 'invite-revoke'],
  ['DELETE', new RegExp(`^/api/agents/([^/]+)/channels/${P}/allowed/(user|group)/.+$`), 'allowed-remove'],
  ['DELETE', /^\/api\/agents\/([^/]+)\/telegram\/allowed\/(user|group)\/.+$/, 'allowed-remove'],
  ['POST', /^\/api\/agents\/([^/]+)\/channel-requests\/\d+\/approve$/, 'channel-request-approve'],
]

/**
 * The action name when this request writes the MAIN agent's channel state,
 * else null. A name that does not decode is treated as the main agent: the
 * handlers would throw on it anyway, and the gate fails closed.
 */
export function mainChannelWriteAction(path: string, method: string, mainAgentId: string): string | null {
  for (const [m, re, action] of MAIN_CHANNEL_WRITES) {
    if (m !== method) continue
    const match = path.match(re)
    if (!match) continue
    let name: string
    try { name = decodeURIComponent(match[1]!) } catch { return action }
    return name === mainAgentId ? action : null
  }
  return null
}

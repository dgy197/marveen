// Preloaded (--require) into the child processes of the credit-gate tests.
// Refuses every connect() to a non-loopback address and to the live CDP ports
// (18800, 18899) and this suite's own blocked test port (18997), BEFORE the
// connect. Self-tested at load against 18997: if the guard does not refuse,
// the process exits 70 before running anything.
'use strict'
const net = require('node:net')
const BLOCKED = new Set([18800, 18899, 18997])
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const orig = net.Socket.prototype.connect
function target(args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0]
  if (first && typeof first === 'object') {
    if (typeof first.path === 'string') return { host: 'unix', port: 0 }
    const port = Number(first.port)
    if (first.host !== undefined && typeof first.host !== 'string') return null
    return Number.isInteger(port) ? { host: first.host === undefined ? 'localhost' : first.host, port } : null
  }
  const port = Number(first)
  return Number.isInteger(port) ? { host: typeof args[1] === 'string' ? args[1] : 'localhost', port } : null
}
net.Socket.prototype.connect = function guarded(...args) {
  const t = target(args)
  if (t === null || (t.host !== 'unix' && (!LOOPBACK.has(t.host) || BLOCKED.has(t.port)))) {
    throw new Error('credit-gate child guard: connect refused')
  }
  return orig.apply(this, args)
}
let refused = false
try {
  net.connect({ host: '127.0.0.1', port: 18997 })
} catch {
  refused = true
}
if (!refused) process.exit(70)

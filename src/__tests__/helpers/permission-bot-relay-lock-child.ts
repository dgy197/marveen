// Child process of permission-bot-relay-lock.test.ts (card d7f586bf).
// Waits for the parent's go-file (barrier), tries acquireRelayLock once, prints
// one JSON line with the result, holds the lock until the release-file appears,
// then releases and exits. Network-free.
//
// Identity probe: /bin/ps is not available under the test sandbox, so each
// child publishes a deterministic identity file (<syncdir>/id-<pid>) and the
// probe reads those; liveness is the real kill(pid, 0).
//
// argv: <lockPath> <syncDir> <name>
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { acquireRelayLock } from '../../permission-bot-relay/lock.js'
import { isPidAlive, type ProcessIdentity, type ProcessProbe } from '../../permission-bot-relay/process-identity.js'

const [lockPath, syncDir, name] = process.argv.slice(2) as [string, string, string]

const probe: ProcessProbe = {
  isAlive: isPidAlive,
  identity(pid: number): ProcessIdentity | null {
    try {
      return JSON.parse(readFileSync(join(syncDir, `id-${pid}`), 'utf8')) as ProcessIdentity
    } catch {
      return null
    }
  },
}

writeFileSync(join(syncDir, `id-${process.pid}`), JSON.stringify({ start: `child-start-${process.pid}`, cmdSha256: 'child-cmd' }))

const sleeper = new Int32Array(new SharedArrayBuffer(4))
function waitFor(path: string): void {
  const deadline = Date.now() + 60_000
  while (!existsSync(path)) {
    if (Date.now() > deadline) throw new Error(`barrier timeout: ${path}`)
    Atomics.wait(sleeper, 0, 0, 1)
  }
}

writeFileSync(join(syncDir, `ready-${name}`), '')
waitFor(join(syncDir, 'go'))
const r = acquireRelayLock(lockPath, { probe })
process.stdout.write(JSON.stringify({ name, pid: process.pid, ok: r.ok, reason: r.ok ? null : r.reason }) + '\n')
writeFileSync(join(syncDir, `done-${name}`), '')
waitFor(join(syncDir, 'release'))
if (r.ok) r.lock.release()

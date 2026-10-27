import { logger } from '../logger.js'
import { backfillEmbeddings, setEmbeddingRefreshArmed, EMBEDDING_REFRESH_MAX_ROWS } from '../db.js'

// Card d4e7fea7, measured 2026-10-17: updateMemory NULLs the vector of an edited
// memory (the old vector describes text that is gone), but the only thing that
// re-embedded NULL rows was the backfill at dashboard boot and the manual
// POST /api/memories/backfill. So an edited memory dropped out of the vector
// branch of the hybrid search until the next restart -- three rows were NULL
// that afternoon, the oldest edited more than an hour earlier.
//
// This runner is the floor: every minute it embeds up to EMBEDDING_REFRESH_MAX_ROWS
// NULL rows, whoever NULLed them (an edit, a save while Ollama was down, a raw
// SQL writer, a model switch). The fast path is the nudge updateMemory sends
// (requestEmbeddingRefresh in db.ts, ~2 s after the edit), which this runner
// arms on start and disarms on stop. Both go through the single-flight
// backfillEmbeddings, so overlapping ticks, the nudge, the route and boot never
// embed the same rows twice, and the vector is written compare-and-set, so a
// row edited during its Ollama call is left NULL for the next pass instead of
// receiving the old text's vector.
//
// A failing pass is logged and retried on the next tick; it never takes the
// process down. The first pass waits 30 s so boot is not a burst of work (the
// boot backfill in index.ts usually has nothing left for it by then).

const INITIAL_DELAY_MS = 30_000
const INTERVAL_MS = 60_000

let initialTimer: ReturnType<typeof setTimeout> | null = null
let intervalTimer: ReturnType<typeof setInterval> | null = null

async function tick(): Promise<void> {
  try {
    const { embedded } = await backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })
    if (embedded > 0) logger.info({ embedded }, 'Embedding refresh')
  } catch (err) {
    logger.error({ err }, 'Embedding refresh failed')
  }
}

export function startEmbeddingRefreshRunner(): void {
  if (initialTimer || intervalTimer) return
  setEmbeddingRefreshArmed(true)
  initialTimer = setTimeout(() => {
    initialTimer = null
    void tick()
    intervalTimer = setInterval(() => { void tick() }, INTERVAL_MS)
    intervalTimer.unref?.()
  }, INITIAL_DELAY_MS)
  initialTimer.unref?.()
}

export function stopEmbeddingRefreshRunner(): void {
  setEmbeddingRefreshArmed(false)
  if (initialTimer) clearTimeout(initialTimer)
  if (intervalTimer) clearInterval(intervalTimer)
  initialTimer = null
  intervalTimer = null
}

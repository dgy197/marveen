// Server-Timing of GET /api/memories?q=...&timing=1 (card 94f8d99f, w3 DW1).
//
// Opt-in, numbers only. The header is `<name>;dur=<ms>` items joined by ", ",
// the names from the fixed sets below, in this fixed order. No `desc`, no free
// text, no user data: a reader (the recall hook) can check it against one
// strict grammar. A stage that did not run is `dur=0`.
//
// `total` runs from the start of the handler to the moment the header is set;
// the JSON serialisation and the gzip happen after that and are outside it.

/** Stage names of a hybrid answer, in header order. */
export const SERVER_TIMING_HYBRID = ['fts', 'embed', 'vecsql', 'vecscore', 'fuse', 'touch', 'fmt', 'total'] as const
/** Stage names of a keyword (non-hybrid) answer, in header order. */
export const SERVER_TIMING_KEYWORD = ['fts', 'touch', 'fmt', 'total'] as const

export type ServerTimingName = typeof SERVER_TIMING_HYBRID[number]

/** The grammar of one header item: <= 6 integer digits, <= 1 decimal. */
const MAX_MS = 999999.9

/**
 * One duration as header text: finite, never negative, one decimal at most,
 * clamped to the grammar's 6 integer digits. NaN / Infinity / a negative value
 * (a clock hiccup) become 0 rather than an invalid header.
 */
export function formatTimingMs(ms: number): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return '0'
  return String(Math.min(MAX_MS, Math.round(ms * 10) / 10))
}

/**
 * The header value for `names` in order; a name missing from `times` counts as
 * 0. Values only, never a string from the caller or a request.
 */
export function serverTimingHeader(
  names: readonly ServerTimingName[],
  times: Partial<Record<ServerTimingName, number>>,
): string {
  return names.map(n => `${n};dur=${formatTimingMs(times[n] ?? 0)}`).join(', ')
}

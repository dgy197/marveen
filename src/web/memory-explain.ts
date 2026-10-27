// explain=1 of GET /api/memories?q=...&mode=hybrid (card 94f8d99f, w3 DW2;
// kanban card 6a2827da): the numbers behind each row's place, so the recall
// hook can log them and a score threshold can be calibrated from them later.
//
// Numbers and nulls only. Never the vector, never any text: the row already
// carries its own content, and the numbers describe the search, not the row.
import type { HybridHit } from '../db.js'

/** The `search` object one row carries when explain=1 asked for it. */
export interface MemorySearchExplain {
  /** Fused RRF score, recency term included, 6 decimals. */
  rrf: number
  /** 1-based rank in the keyword branch; null if that branch did not return the row. */
  fts_rank: number | null
  /** 1-based rank in the vector branch; null if that branch did not return the row. */
  vec_rank: number | null
  /** Cosine similarity to the query, 4 decimals; null if the vector branch did not return the row. */
  cos: number | null
}

const round = (x: number, decimals: number): number => {
  const f = Math.pow(10, decimals)
  const r = Math.round(x * f) / f
  return r === 0 ? 0 : r
}

const rankOrNull = (r: number | null): number | null =>
  typeof r === 'number' && Number.isInteger(r) && r >= 1 ? r : null

/**
 * The `search` object of one fused hybrid row. A value that is not a usable
 * number (never produced by fuseRanked, which counts a non-finite cosine as 0)
 * becomes null, or 0 for the score, instead of a NaN that JSON would turn into
 * null in a field the reader expects to be a number.
 */
export function explainHit(hit: HybridHit): MemorySearchExplain {
  const cos = hit.cosine
  return {
    rrf: Number.isFinite(hit.score) ? round(hit.score, 6) : 0,
    fts_rank: rankOrNull(hit.ftsRank),
    vec_rank: rankOrNull(hit.vecRank),
    cos: typeof cos === 'number' && Number.isFinite(cos) ? round(cos, 4) : null,
  }
}

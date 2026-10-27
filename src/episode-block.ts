// 3e9f6c28 c): episode block for the context-guard handoff request and the
// PreCompact agent-hook prompt.
//
// Why: HANDOFF.md and the PreCompact notes are free-form, so a fresh session
// (or a memory search) cannot rely on any particular field being there. An
// episode memory has the same six fields every time (goal, what happened,
// decision, failure, open, next), which is what the multi-session questions of
// the memory benchmark need.
//
// sector: the memories table has sector IN ('semantic','episodic'), but POST
// /api/memories always inserts 'semantic' (saveAgentMemory) and ignores an
// unknown "sector" field. Until the endpoint takes it, the episode is found by
// its keywords ("epizod, episodic, ugynok:<id>"). The payload still carries
// "sector":"episodic" so it is correct the day the endpoint honours it.
//
// The text is plain prose with no percent sign and none of the alarm words the
// handoff tone test forbids for the idle tier. It never throws: a failed
// episode must not break the handoff it rides on (the prompt itself tells the
// agent to skip a failed save silently).

export const EPISODE_FIELDS = ['Cél', 'Mi történt', 'Döntés', 'Kudarc', 'Nyitott', 'Legközelebb'] as const

export interface EpisodeStepOpts {
  webPort: number | string
  projectRoot: string
  /** Agent id; omitted in the PreCompact template, where the agent derives it from CLAUDE.md. */
  agentName?: string
  /** Stale-refresh request: the agent already saved an episode earlier in this sequence. */
  refresh?: boolean
}

// The JSON reaches curl on stdin from a quoted heredoc in the SAME Bash call: no
// temp file exists, so there is no shared /tmp name to collide on or to clean up.
// --max-time keeps a hung dashboard from stalling the handoff or the compaction.
function curlLine(opts: EpisodeStepOpts): string {
  return (
    `curl -s --max-time 10 -X POST http://localhost:${opts.webPort}/api/memories ` +
    `-H 'Content-Type: application/json' ` +
    `-H "Authorization: Bearer $(cat ${opts.projectRoot}/store/.dashboard-token)" ` +
    `--data-binary @-`
  )
}

function payloadShape(who: string): string {
  const fields = EPISODE_FIELDS.map((f) => `${f}: ...`).join(' | ')
  return (
    `{"agent_id":"${who}","category":"cold","sector":"episodic",` +
    `"keywords":"epizod, episodic, ugynok:${who}, ÉÉÉÉ-HH-NN",` +
    `"content":"[Epizód ÉÉÉÉ-HH-NN] ${fields}"}`
  )
}

const FIELD_RULES =
  `Mind a hat mező 1-2 mondat, ami nincs, ahhoz írd: nincs. ` +
  `Titkot, tokent, jelszót ne írj bele. A mai dátumot a date parancs adja (ÉÉÉÉ-HH-NN).`

/**
 * Step appended to a context-guard handoff request. The episode goes FIRST and
 * HANDOFF.md last, because the appearance of the fresh HANDOFF.md is what lets
 * the guard restart the session: a save placed after it could be cut off.
 */
export function episodeHandoffStep(opts: EpisodeStepOpts): string {
  try {
    const who = opts.agentName && opts.agentName.trim() ? opts.agentName.trim() : 'SAJAT_NEVED'
    const scope = opts.refresh
      ? `Ha ebben a sorozatban már mentettél epizód-emléket, most csak az azóta történtekről ments egy újat; ha nem, a teljes munkamenetről. `
      : `A most lezáruló munkamenetről ments EGY epizód-emléket. `
    return (
      ` KIEGÉSZÍTÉS az előző utasításhoz (az ÁLLJ MEG ennek a lépésnek a végére szól): a HANDOFF.md-t csak UTOLSÓ lépésként írd, mert annak megjelenése indítja az újraindítást. ` +
      `Előtte: ${scope}` +
      `Hat mező, ebben a sorrendben: ${EPISODE_FIELDS.join(' / ')}. ${FIELD_RULES} ` +
      `Egyetlen Bash-hívásban küldd el, a JSON-t idézett heredoc-kal (<<'EPIZOD_JSON_3E9F'; a JSON EGYETLEN sorban álljon, utána egy külön sorban csak ez: EPIZOD_JSON_3E9F) adva a curl-nek, ideiglenes fájl nélkül: ${curlLine(opts)} ` +
      `A JSON alakja: ${payloadShape(who)} ` +
      `Ha a mentés hibázik (nem jön vissza id), hagyd ki szó nélkül, és írd tovább a HANDOFF.md-t.`
    )
  } catch {
    return ''
  }
}

/**
 * Section 4 of the PreCompact agent-hook prompt (sections 1-3 are the memory
 * save, the skill reflection and the task-state save). Placeholders such as
 * {{WEB_PORT}} stay as they are: the scaffold resolves them per install.
 */
export function episodePrecompactStep(opts: EpisodeStepOpts): string {
  try {
    const who = opts.agentName && opts.agentName.trim() ? opts.agentName.trim() : 'SAJAT_NEVED'
    return (
      `## 4. Epizód-emlék (hat mező)\n` +
      `A tömörítés előtt ments EGY epizód-emléket az eddigi munkamenetről, mindig ugyanazzal a hat mezővel: ${EPISODE_FIELDS.join(' / ')}. ${FIELD_RULES}\n\n` +
      `Egyetlen Bash-hívásban küldd el, a JSON-t idézett heredoc-kal (<<'EPIZOD_JSON_3E9F'; a JSON EGYETLEN sorban álljon, utána egy külön sorban csak ez: EPIZOD_JSON_3E9F) adva a curl-nek, ideiglenes fájl nélkül:\n` +
      `${curlLine(opts)}\n\n` +
      `A JSON alakja: ${payloadShape(who)}\n\n` +
      `Ha csak beszélgetés volt, és nincs mit rögzíteni, hagyd ki. Ha a mentés hibázik (nem jön vissza id), hagyd ki szó nélkül.`
    )
  } catch {
    return ''
  }
}

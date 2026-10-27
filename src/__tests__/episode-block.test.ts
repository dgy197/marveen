import { spawnSync } from 'node:child_process'
// 3e9f6c28 c): the six-field episode step in the context-guard handoff request
// and in the PreCompact agent-hook prompt.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  EPISODE_FIELDS,
  episodeHandoffStep,
  episodePrecompactStep,
} from '../episode-block.js'
import {
  handoffPrompt,
  idleFlushHandoffPrompt,
  dailyHandoffPrompt,
  staleRefreshHandoffPrompt,
} from '../web/context-guard-runner.js'

const PATH = '/tmp/agents/x/HANDOFF.md'
const OPTS = { webPort: 3420, projectRoot: '/opt/marveen', agentName: 'ezermester' }

describe('episodeHandoffStep', () => {
  const s = episodeHandoffStep(OPTS)

  it('names all six fields, in order', () => {
    expect(EPISODE_FIELDS).toHaveLength(6)
    let from = 0
    for (const f of EPISODE_FIELDS) {
      const at = s.indexOf(f, from)
      expect(at, f).toBeGreaterThanOrEqual(from)
      from = at
    }
  })

  it('saves a cold episodic memory with the episode keywords and the given agent id', () => {
    expect(s).toContain('"category":"cold"')
    expect(s).toContain('"sector":"episodic"')
    expect(s).toContain('"agent_id":"ezermester"')
    expect(s).toContain('epizod, episodic, ugynok:ezermester')
    expect(s).toContain('http://localhost:3420/api/memories')
    expect(s).toContain('/opt/marveen/store/.dashboard-token')
  })

  it('puts the episode before HANDOFF.md, which is written last', () => {
    expect(s).toContain('UTOLSÓ lépésként')
    expect(s.indexOf('epizód-emléket')).toBeLessThan(s.indexOf('Hat mező'))
  })

  it('sends the JSON on stdin from a quoted heredoc in one call: no temp file, never inline in -d', () => {
    expect(s).toContain("<<'EPIZOD_JSON_3E9F'")
    expect(s).toContain('--data-binary @-')
    expect(s).toContain('Egyetlen Bash-hívásban')
    expect(s).not.toContain('/tmp/')
    expect(s).not.toContain(' -d ')
  })

  it('the curl call has a time limit (a hung dashboard must not stall the handoff)', () => {
    expect(s).toContain('curl -s --max-time 10 -X POST')
  })

  it('tells the agent to skip a failed save silently and keep writing the handoff', () => {
    expect(s).toContain('hagyd ki szó nélkül')
    expect(s).toContain('HANDOFF.md')
  })

  it('refresh variant only asks for what happened since', () => {
    const r = episodeHandoffStep({ ...OPTS, refresh: true })
    expect(r).toContain('azóta történtekről')
    expect(s).not.toContain('azóta történtekről')
  })

  it('without an agent name it falls back to the placeholder the PreCompact prompt uses', () => {
    expect(episodeHandoffStep({ webPort: 3420, projectRoot: '/x' })).toContain('"agent_id":"SAJAT_NEVED"')
  })

  it('never throws on odd input', () => {
    expect(() => episodeHandoffStep({ webPort: NaN, projectRoot: '', agentName: '   ' })).not.toThrow()
  })
})

describe('the step keeps every handoff tier\'s tone invariants when appended', () => {
  const idle = idleFlushHandoffPrompt(501_234, 45, PATH) + episodeHandoffStep(OPTS)
  const act = handoffPrompt(93, PATH) + episodeHandoffStep(OPTS)
  const daily = dailyHandoffPrompt('04:00', PATH) + episodeHandoffStep(OPTS)
  const stale = staleRefreshHandoffPrompt(37, PATH) + episodeHandoffStep({ ...OPTS, refresh: true })

  it('idle: still no alarm words and no percent sign', () => {
    expect(idle).not.toContain('kritikus')
    expect(idle).not.toContain('NE folytasd')
    expect(idle).not.toContain('%')
  })

  it('act and daily: the routine wording did not leak in', () => {
    for (const p of [act, daily]) {
      expect(p).not.toContain('Rutin karbantartás')
    }
    expect(daily).not.toContain('kritikus')
  })

  it('stale: still an update, not a first write', () => {
    expect(stale).not.toContain('írj HANDOFF.md-t')
    expect(stale).toContain('frissítsd')
  })

  it('all four keep the envelope, the path and ÁLLJ MEG, and stay distinct', () => {
    for (const p of [idle, act, daily, stale]) {
      expect(p.startsWith('[CONTEXT-GUARD]')).toBe(true)
      expect(p).toContain(PATH)
      expect(p).toContain('ÁLLJ MEG')
    }
    expect(new Set([idle, act, daily, stale]).size).toBe(4)
  })
})

describe('episodePrecompactStep and the template', () => {
  const step = episodePrecompactStep({ webPort: '{{WEB_PORT}}', projectRoot: '{{PROJECT_ROOT}}' })
  const tpl = JSON.parse(readFileSync(join(process.cwd(), 'templates/settings.json.template'), 'utf-8'))
  const prompt: string = tpl.hooks.PreCompact[0].hooks[0].prompt

  it('the template PreCompact prompt carries the step verbatim (placeholders unresolved)', () => {
    expect(prompt).toContain(step)
  })

  it('the step comes after the existing three sections, which are untouched', () => {
    const at = (needle: string) => prompt.indexOf(needle)
    expect(at('## 1. Memória mentés')).toBeGreaterThan(-1)
    expect(at('## 1. Memória mentés')).toBeLessThan(at('## 2. Skill reflexió'))
    expect(at('## 2. Skill reflexió')).toBeLessThan(at('## 3. Aktív task-state mentés'))
    expect(at('## 3. Aktív task-state mentés')).toBeLessThan(at('## 4. Epizód-emlék'))
    expect(prompt).toContain('Négy dolgot csinálj')
  })

  it('the step sends via stdin heredoc with a curl time limit and leaves no /tmp file', () => {
    expect(step).toContain('curl -s --max-time 10 -X POST')
    expect(step).toContain('--data-binary @-')
    expect(step).toContain("<<'EPIZOD_JSON_3E9F'")
    expect(step).not.toContain('/tmp/')
    expect(step).not.toContain(' -d ')
  })

  it('names the six fields and the silent-skip rule', () => {
    for (const f of EPISODE_FIELDS) expect(step).toContain(f)
    expect(step).toContain('hagyd ki szó nélkül')
    expect(step).toContain('"sector":"episodic"')
  })

  it('the timeout still covers the longer prompt', () => {
    expect(tpl.hooks.PreCompact[0].hooks[0].timeout).toBeGreaterThanOrEqual(180)
  })
})

describe('runner wiring', () => {
  const src = readFileSync(join(process.cwd(), 'src/web/context-guard-runner.ts'), 'utf-8')
  const caseStart = src.indexOf("case 'request-handoff':")
  const caseEnd = src.indexOf("case 'restart':", caseStart)
  const block = src.slice(caseStart, caseEnd)

  it('the episode step is appended to the directive text of the request-handoff case', () => {
    expect(block).toContain('episodeHandoffStep({')
    expect(block).toContain('agentName: name')
    expect(block.indexOf(': handoffPrompt(')).toBeLessThan(block.indexOf('episodeHandoffStep('))
    // still goes through the authenticated directive primitive
    expect(block).toContain('sendSystemDirective(')
  })

  it('the stale-refresh tier is the one that passes refresh', () => {
    // v1.45.0: the runner reads promptReason (decision.reason, or the stored reason on a resend);
    // the assertion is the same prefix check on the field the runner really uses.
    expect(block).toMatch(/refresh: promptReason\.startsWith\(STALE_REFRESH_REASON_PREFIX\)/)
  })
})

describe('B8: the heredoc delimiter cannot be closed by episode text', () => {
  it('uses the unique delimiter and asks for single-line JSON, never the bare JSON delimiter', () => {
    for (const out of [
      episodePrecompactStep({ webPort: 3420, projectRoot: '/x' }),
      episodeHandoffStep({ webPort: 3420, projectRoot: '/x', agentName: 'brainy' }),
    ]) {
      expect(out).toContain("<<'EPIZOD_JSON_3E9F'")
      expect(out).toContain('EGYETLEN sorban')
      expect(out).not.toContain("<<'JSON'")
    }
  })
  it('a body line that is only JSON does not end the heredoc', () => {
    const body = '{"content":"cél: x"}\nJSON\necho B8_PWNED'
    const r = spawnSync('bash', ['-c', `cat <<'EPIZOD_JSON_3E9F'\n${body}\nEPIZOD_JSON_3E9F`], { encoding: 'utf8' })
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(body + '\n')
  })
})

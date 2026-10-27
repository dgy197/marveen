import { readFileSync, existsSync, readdirSync, statSync, realpathSync } from 'node:fs'
import { join, relative, isAbsolute, sep, resolve } from 'node:path'
import { homedir } from 'node:os'
import { saveAgentMemory } from '../../db.js'
import { MAIN_AGENT_ID, OLLAMA_URL, PROJECT_ROOT, STORE_DIR } from '../../config.js'
import { readEnvFile } from '../../env.js'
import { channelStateDir, type ChannelProviderType } from '../../channel-provider.js'
import { logger } from '../../logger.js'
import { readBody, json } from '../http-helpers.js'
import { callerLabel, MIGRATE_ROOTS_ENV } from '../admin-switch.js'
import type { RouteContext } from './types.js'

// Longest run of characters a single memory row may hold. Anything longer is
// split into several rows; it is never cut short. See CHUNK_MIN_TAIL for the
// one case where a chunk is allowed to exceed this.
const MEMORY_CHUNK_CHARS = 2000
const DOCUMENT_CHUNK_CHARS = 3000

// A section shorter than this is not worth its own memory row. It is the
// threshold the importer has always used; it is applied to the SOURCE section,
// before chunking, so a long section never loses its tail to it.
const SECTION_MIN_CHARS = 20

// A trailing chunk shorter than this is appended to the chunk before it rather
// than becoming a memory row of its own. That makes the last chunk longer than
// maxLen by up to this much, which is the deliberate trade: a slightly long row
// beats a row holding half a sentence, and beats dropping the tail.
const CHUNK_MIN_TAIL = 20

// Never cut before this fraction of the window. Without a floor, a paragraph
// break early in the window would produce a stream of tiny chunks.
const BOUNDARY_FLOOR = 0.6

/**
 * Split `text` into chunks of at most `maxLen` characters, preferring to cut at
 * a paragraph break, then a sentence end, then any whitespace. Falls back to a
 * hard cut only when the window holds no boundary at all (one very long word).
 *
 * The contract that matters: the concatenation of the result contains every
 * non-whitespace character of the input. Nothing is discarded. This is the fix
 * for the importer truncating each section at 2000 characters (GH #1024, which
 * measured 30.4% of the source text lost on a 20 file run, with no sign of it
 * in the response).
 */
export function chunkText(text: string, maxLen: number): string[] {
  const trimmed = text.trim()
  if (!trimmed) return []
  if (trimmed.length <= maxLen) return [trimmed]

  const chunks: string[] = []
  const floor = Math.floor(maxLen * BOUNDARY_FLOOR)
  let rest = trimmed

  while (rest.length > maxLen) {
    const window = rest.slice(0, maxLen)
    let cut = window.lastIndexOf('\n\n')

    if (cut < floor) {
      const sentence = Math.max(
        window.lastIndexOf('. '), window.lastIndexOf('.\n'),
        window.lastIndexOf('! '), window.lastIndexOf('!\n'),
        window.lastIndexOf('? '), window.lastIndexOf('?\n'),
      )
      cut = sentence >= floor ? sentence + 1 : -1
    }
    if (cut < floor) {
      const space = window.lastIndexOf(' ')
      // A hard cut at maxLen is the last resort, not the default.
      cut = space >= floor ? space : maxLen
    }

    chunks.push(rest.slice(0, cut).trim())
    rest = rest.slice(cut).trim()
  }

  if (rest) {
    if (chunks.length > 0 && rest.length < CHUNK_MIN_TAIL) {
      chunks[chunks.length - 1] = `${chunks[chunks.length - 1]}\n${rest}`
    } else {
      chunks.push(rest)
    }
  }

  return chunks
}

// Card 053f4e66: /api/migrate/run reads the files named in its request body.
// It used to read ANY path it was given -- through the one shared Bearer, any
// file the dashboard user can read, into memory rows anyone with the token can
// list. A run may now read only a file that a scan of this process listed,
// recently: the scan records the realpath of its root and of every file it
// reported, and the run compares realpaths, so "../", an absolute path
// elsewhere, and a symlink pointing out of the root are all refused (403)
// before anything is read. The registry is in memory: after a dashboard
// restart the UI simply scans again.
const SCAN_TTL_MS = 60 * 60 * 1000
const MAX_SCANS = 20
const scanRegistry = new Map<string, { expires: number; files: Set<string> }>()

/** true iff `child` (a realpath) is strictly inside `root` (a realpath). */
function isStrictlyUnder(root: string, child: string): boolean {
  const rel = relative(root, child)
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel)
}

// realpathSync.native (realpath(3)), not the JS realpathSync: on a
// case-insensitive APFS volume the JS version hands back the letter case it
// was given, so ".../MARVEEN/STORE" would not compare equal to the protected
// ".../marveen/store" in relative() and would slip past forbiddenReason().
// The native call returns the on-disk case (053f4e66, BE round 3).
function realOrNull(p: string): string | null {
  try { return realpathSync.native(p) } catch { return null }
}

function recordScan(root: string, files: Set<string>, now = Date.now()): void {
  for (const [k, v] of scanRegistry) if (v.expires < now) scanRegistry.delete(k)
  scanRegistry.delete(root)
  scanRegistry.set(root, { expires: now + SCAN_TTL_MS, files })
  while (scanRegistry.size > MAX_SCANS) scanRegistry.delete(scanRegistry.keys().next().value as string)
}

/** The realpath of a run path if a live scan listed it, else null. Reads no file content. */
function scannedRealPath(p: unknown, now = Date.now()): string | null {
  if (typeof p !== 'string' || p.length === 0 || p.includes('\0')) return null
  const real = realOrNull(p)
  if (!real) return null
  for (const [root, v] of scanRegistry) {
    if (v.expires >= now && v.files.has(real) && isStrictlyUnder(root, real)) return real
  }
  return null
}

// Card 053f4e66 (M1): the scan root itself comes from an allowlist. The
// install's .env MIGRATE_ROOTS (':'-separated absolute folders, read per
// request, never writable through the Bearer: admin-switch.ts) names where a
// migration source may live; without it every scan is 403. Whatever the list
// says, these are always refused after realpath: the store, the install root
// and everything below it, ~/.claude, ~/.config, every main channel state dir,
// and any path with a dot-folder component.
const PROVIDERS: ChannelProviderType[] = ['telegram', 'slack', 'discord', 'googlechat', 'teams']

function isUnderOrEqual(base: string, p: string): boolean {
  const rel = relative(base, p)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

function forbiddenBases(): string[] {
  const home = homedir()
  const raw = [STORE_DIR, PROJECT_ROOT, join(home, '.claude'), join(home, '.config'), ...PROVIDERS.map(p => channelStateDir(p))]
  const out = new Set<string>()
  for (const b of raw) {
    out.add(resolve(b))
    const real = realOrNull(b)
    if (real) out.add(real)
  }
  return [...out]
}

/** Why `p` (absolute, ideally a realpath) may never be scanned, or null. */
function forbiddenReason(p: string): string | null {
  if (p.split(sep).some(c => c.startsWith('.') && c !== '.' && c !== '..')) return 'dot-folder'
  for (const b of forbiddenBases()) if (isUnderOrEqual(b, p)) return 'protected'
  return null
}

/** The usable allowlist roots (realpaths), forbidden ones dropped. */
function migrateRoots(): string[] {
  const raw = readEnvFile([MIGRATE_ROOTS_ENV])[MIGRATE_ROOTS_ENV] ?? ''
  const roots: string[] = []
  for (const part of raw.split(':')) {
    const t = part.trim()
    if (!t || !isAbsolute(t)) continue
    const real = realOrNull(t)
    if (real && !forbiddenReason(real)) roots.push(real)
  }
  return roots
}

/** Test hook: forget every recorded scan. */
export function _resetMigrateScansForTest(): void { scanRegistry.clear() }

export async function tryHandleMigrate(ctx: RouteContext): Promise<boolean> {
  const { req, res, path, method } = ctx

  if (path === '/api/migrate/scan' && method === 'POST') {
    const body = await readBody(req)
    const { sourcePath } = JSON.parse(body.toString()) as { sourcePath: string; sourceType: string }

    if (typeof sourcePath !== 'string' || !sourcePath.trim()) { json(res, { error: 'Útvonal megadása kötelező' }, 400); return true }

    // M1: allowlist first, so a refused path does not even learn whether it exists.
    const roots = migrateRoots()
    const refuseScan = (reason: string): true => {
      logger.warn({ caller: callerLabel(req), at: new Date().toISOString(), reason }, 'Migrate scan refused')
      json(res, { error: `A feltérképezés csak a ${MIGRATE_ROOTS_ENV} (.env) mappáiban engedélyezett, védett és pont-mappán kívül.`, reason }, 403)
      return true
    }
    if (roots.length === 0) return refuseScan('migrate_roots_missing')
    const rootReal = realOrNull(sourcePath)
    const where = rootReal ?? resolve(sourcePath)
    const bad = forbiddenReason(where)
    if (bad) return refuseScan(bad)
    if (!roots.some(r => isUnderOrEqual(r, where))) return refuseScan('outside_migrate_roots')
    if (!rootReal || !existsSync(rootReal)) { json(res, { error: 'A megadott útvonal nem létezik' }, 404); return true }
    if (!statSync(rootReal).isDirectory()) { json(res, { error: 'A megadott útvonal nem mappa' }, 400); return true }

    const findings: { type: string; path: string; name: string; size: number }[] = []
    const scannedReal = new Set<string>()

    // Only a regular file whose realpath stays strictly under the scanned root
    // is listed (053f4e66): a symlink pointing out of the root is skipped.
    const listable = (filePath: string): string | null => {
      const real = realOrNull(filePath)
      if (!real || !isStrictlyUnder(rootReal, real) || forbiddenReason(real)) return null
      try { return statSync(real).isFile() ? real : null } catch { return null }
    }

    const addFinding = (type: string, filePath: string) => {
      const real = listable(filePath)
      if (real) {
        const stat = statSync(real)
        findings.push({ type, path: filePath, name: filePath.split('/').pop() || '', size: stat.size })
        scannedReal.add(real)
      }
    }

    const knownFiles = [
      { pattern: 'MEMORY.md', type: 'memory-cold' },
      { pattern: 'memory/hot/HOT_MEMORY.md', type: 'memory-hot' },
      { pattern: 'memory/warm/WARM_MEMORY.md', type: 'memory-warm' },
      { pattern: 'SOUL.md', type: 'personality' },
      { pattern: 'USER.md', type: 'profile' },
      { pattern: 'HEARTBEAT.md', type: 'heartbeat' },
      { pattern: 'AGENTS.md', type: 'config' },
      { pattern: 'TOOLS.md', type: 'config' },
      { pattern: 'CLAUDE.md', type: 'config' },
    ]

    for (const kf of knownFiles) {
      addFinding(kf.type, join(sourcePath, kf.pattern))
    }

    try {
      const scanDirs = ['memory', 'memories', 'bank', 'notes', '']
      for (const dir of scanDirs) {
        const scanPath = dir ? join(sourcePath, dir) : sourcePath
        if (!existsSync(scanPath)) continue
        const files = readdirSync(scanPath).filter(f =>
          // Dotfiles are never listed (053f4e66): e.g. ~/.claude/.credentials.json.
          !f.startsWith('.') &&
          (f.endsWith('.md') || f.endsWith('.txt') || f.endsWith('.json')) &&
          !['package.json', 'tsconfig.json', 'package-lock.json', '.mcp.json'].includes(f)
        )
        for (const f of files) {
          const fullPath = join(scanPath, f)
          if (findings.some(fi => fi.path === fullPath)) continue
          try {
            const real = listable(fullPath)
            if (!real) continue
            const stat = statSync(real)
            if (stat.isFile() && stat.size > 20) {
              const lower = f.toLowerCase()
              let type = 'memory'
              if (lower.includes('soul') || lower.includes('personality')) type = 'personality'
              else if (lower.includes('user') || lower.includes('profile')) type = 'profile'
              else if (lower.includes('heartbeat')) type = 'heartbeat'
              else if (lower.includes('cron') || lower.includes('schedule')) type = 'schedule'
              else if (lower.match(/^\d{4}-\d{2}-\d{2}/)) type = 'daily-log'
              findings.push({ type, path: fullPath, name: f, size: stat.size })
              scannedReal.add(real)
            }
          } catch {}
        }
      }
    } catch {}

    recordScan(rootReal, scannedReal)

    json(res, {
      ok: true,
      sourcePath,
      findings,
      summary: {
        personality: findings.filter(f => f.type === 'personality').length,
        profile: findings.filter(f => f.type === 'profile').length,
        memory: findings.filter(f => f.type.startsWith('memory')).length,
        heartbeat: findings.filter(f => f.type === 'heartbeat').length,
        config: findings.filter(f => f.type === 'config').length,
        dailyLog: findings.filter(f => f.type === 'daily-log').length,
        schedule: findings.filter(f => f.type === 'schedule').length,
        total: findings.length,
      }
    })
    return true
  }

  if (path === '/api/migrate/run' && method === 'POST') {
    const body = await readBody(req)
    const { findings: requested, agentId: targetAgent } = JSON.parse(body.toString()) as {
      findings: { type: string; path: string; name: string }[];
      agentId: string
    }

    // 053f4e66: every path must be a file a live scan listed (realpath
    // compared); one that is not refuses the whole run before anything is
    // read. The files are then read through their checked realpath.
    if (!Array.isArray(requested)) { json(res, { error: 'findings tömb kötelező' }, 400); return true }
    const findings: { type: string; path: string; name: string }[] = []
    let refused = 0
    for (const f of requested) {
      const real = f && typeof f === 'object' ? scannedRealPath((f as { path?: unknown }).path) : null
      if (!real) { refused++; continue }
      findings.push({ type: String(f.type ?? ''), path: real, name: String(f.name ?? '') })
    }
    if (refused > 0) {
      logger.warn({ caller: callerLabel(req), at: new Date().toISOString(), refused }, 'Migrate run refused: a path outside the scanned folders')
      json(res, { error: 'Csak a feltérképezett mappákban talált fájl költöztethető; futtasd újra a feltérképezést.', refused }, 403)
      return true
    }

    const agentId = targetAgent || MAIN_AGENT_ID
    let imported = 0
    const stats = { hot: 0, warm: 0, cold: 0, shared: 0 }
    const details: string[] = []

    // Character accounting. The old importer reported the number of rows it
    // wrote, which says nothing about how much of the source arrived: it was
    // possible (and measured, GH #1024) to lose 30% of the text and still read
    // a clean success. These two totals go back in the response so the caller
    // can see the difference instead of having to measure the database.
    let sourceChars = 0
    let importedChars = 0
    let skippedShortChars = 0

    // Saves one source document as however many rows it needs, labelling the
    // parts when there is more than one so a reader can tell they belong together.
    const saveDocument = (label: string, content: string, keywords: string) => {
      const parts = chunkText(content, DOCUMENT_CHUNK_CHARS)
      parts.forEach((part, i) => {
        const suffix = parts.length > 1 ? ` (${i + 1}/${parts.length})` : ''
        saveAgentMemory(agentId, `[${label}${suffix}] ${part}`, 'warm', keywords, true)
        stats.warm++
        imported++
        importedChars += part.length
      })
      return parts.length
    }

    for (const f of findings.filter(fi => fi.type === 'personality')) {
      try {
        const content = readFileSync(f.path, 'utf-8')
        sourceChars += content.trim().length
        const parts = saveDocument('Importált személyiség', content, 'személyiség, soul, import')
        details.push(`Személyiség: ${f.name}${parts > 1 ? ` (${parts} részben)` : ''}`)
      } catch {}
    }

    for (const f of findings.filter(fi => fi.type === 'profile')) {
      try {
        const content = readFileSync(f.path, 'utf-8')
        sourceChars += content.trim().length
        const parts = saveDocument('Importált felhasználói profil', content, 'felhasználó, profil, import')
        details.push(`Profil: ${f.name}${parts > 1 ? ` (${parts} részben)` : ''}`)
      } catch {}
    }

    for (const f of findings.filter(fi => fi.type === 'heartbeat')) {
      try {
        const content = readFileSync(f.path, 'utf-8')
        sourceChars += content.trim().length
        const parts = saveDocument('Importált heartbeat konfig', content, 'heartbeat, konfig, import')
        details.push(`Heartbeat: ${f.name}${parts > 1 ? ` (${parts} részben)` : ''}`)
      } catch {}
    }

    const memoryFindings = findings.filter(fi =>
      fi.type.startsWith('memory') || fi.type === 'config' || fi.type === 'daily-log'
    )

    const chunks: string[] = []

    // Every section that clears SECTION_MIN_CHARS is chunked, never truncated.
    // The length test stays on the source section: a 6000 character section is
    // long enough to keep, and it keeps all 6000, in three rows.
    const addSection = (text: string) => {
      const section = text.trim()
      if (section.length <= SECTION_MIN_CHARS) { skippedShortChars += section.length; return }
      chunks.push(...chunkText(section, MEMORY_CHUNK_CHARS))
    }

    for (const f of memoryFindings) {
      try {
        const content = readFileSync(f.path, 'utf-8')
        sourceChars += content.trim().length
        const ext = f.name.split('.').pop()?.toLowerCase()
        if (ext === 'json') {
          try {
            const data = JSON.parse(content)
            if (Array.isArray(data)) {
              for (const item of data) {
                const text = typeof item === 'object' ? (item.content || item.text || JSON.stringify(item)) : String(item)
                addSection(String(text))
              }
            } else if (typeof data === 'object') {
              for (const [k, v] of Object.entries(data)) {
                addSection(`${k}: ${v}`)
              }
            }
          } catch { addSection(content) }
        } else {
          const sections = ext === 'md' ? content.split(/\n(?=##?\s)/) : content.split(/\n\n+/)
          for (const section of sections) addSection(section)
        }
      } catch {}
    }

    if (chunks.length > 0) {
      let categorizeModel: string | null = null
      // Why the reason is carried and not just the null: an install whose only
      // Ollama model is an embedding model (needed for vector search) gets no
      // categoriser, so every row lands in `warm` with empty keywords. That is
      // a real degradation of the import and it used to happen in silence
      // (GH #1024, second finding).
      let categorizeUnavailable: string | null = null
      try {
        const modelsResp = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(3000) })
        const modelsData = await modelsResp.json() as { models?: { name: string }[] }
        const available = (modelsData.models || []).filter(m => !m.name.includes('embed')).map(m => m.name)
        categorizeModel = available.find(m => m.includes('gemma4')) || available[0] || null
        if (!categorizeModel) {
          categorizeUnavailable = 'nincs kategorizálásra alkalmas Ollama modell (csak embedding modell érhető el)'
        }
      } catch {
        categorizeUnavailable = 'az Ollama nem válaszolt'
      }

      for (const chunk of chunks) {
        try {
          let tier = 'warm'
          let keywords = ''

          if (categorizeModel) {
            const catResp = await fetch(`${OLLAMA_URL}/api/generate`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                model: categorizeModel,
                prompt: `Categorize this memory. Respond ONLY with JSON:\n{"tier":"warm","keywords":"kw1, kw2"}\nTiers: hot (active/urgent), warm (preferences/config), cold (lessons/archive), shared (multi-agent)\n\nMemory: "${chunk.slice(0, 400)}"`,
                stream: false,
              }),
              signal: AbortSignal.timeout(90000),
            })
            const catData = await catResp.json() as { response?: string }
            const jsonMatch = (catData.response || '').match(/\{[\s\S]*\}/)
            if (jsonMatch) {
              const parsed = JSON.parse(jsonMatch[0])
              tier = ['hot', 'warm', 'cold', 'shared'].includes(parsed.tier) ? parsed.tier : 'warm'
              keywords = parsed.keywords || ''
            }
          }

          saveAgentMemory(agentId, chunk, tier, keywords, true)
          stats[tier as keyof typeof stats]++
          imported++
          importedChars += chunk.length

          if (chunks.indexOf(chunk) < chunks.length - 1) {
            await new Promise(r => setTimeout(r, 200))
          }
        } catch {
          saveAgentMemory(agentId, chunk, 'warm', '', true)
          stats.warm++
          imported++
          importedChars += chunk.length
        }
      }

      details.push(`${chunks.length} memória chunk feldolgozva`)
      if (categorizeUnavailable) {
        details.push(`Kategorizálás kimaradt (${categorizeUnavailable}), ezért minden sor warm lett, kulcsszavak nélkül`)
      }
    }

    // What the difference means, so the number is readable: source is every
    // character in the selected files, imported is every character written to
    // `memories`. The gap is structural (JSON syntax, blank lines between
    // sections, markdown heading separators) plus the sections below the
    // minimum length, which are counted separately. After the chunking fix no
    // kept section loses its tail, so a large unexplained gap is a bug report,
    // not normal operation.
    const chars = { source: sourceChars, imported: importedChars, skippedShortSections: skippedShortChars }
    if (sourceChars > 0) {
      const pct = Math.round((importedChars / sourceChars) * 1000) / 10
      details.push(`Karakterek: ${importedChars} / ${sourceChars} importálva (${pct}%), rövid szekciókból kihagyva: ${skippedShortChars}`)
    }

    logger.info({ agentId, imported, stats, chars }, 'Költöztetés kész')
    json(res, { ok: true, imported, stats, details, chars })
    return true
  }

  return false
}

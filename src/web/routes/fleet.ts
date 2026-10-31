import { logger } from '../../logger.js'
import { FLEET_IMPORT_APPLY_ENV, isAdminSwitchOn, callerLabel } from '../admin-switch.js'
import { readBody, json } from '../http-helpers.js'
import { exportFleet, importFleet, MIN_VAULT_PASSWORD_LEN, UserFacingError, type ExportedFleet } from '../fleet-transfer.js'
import { serializeSkillsDir } from '../skills-dir-queue.js'
import { writeAgentSettingsFromProfile } from '../agent-scaffold.js'
import { loadProfileTemplate } from '../profiles.js'
import { execGateApplies, admitCodeExecAdmin, codeExecAuditTrail } from '../code-exec-admin.js'
import type { RouteContext } from './types.js'

// Card 053f4e66: applying a fleet import overwrites the main agent's persona,
// settings, channel pairing (access.json), the .env identity and the DB, all
// behind the one shared dashboard token. On this install it is OFF unless the
// .env says FLEET_IMPORT_APPLY_ENABLED=1 (admin-switch.ts). The dry run (no
// apply) is untouched: it only reads.
export { FLEET_IMPORT_APPLY_ENV }

export function isFleetImportApplyEnabled(): boolean {
  return isAdminSwitchOn(FLEET_IMPORT_APPLY_ENV)
}

export async function tryHandleFleet(ctx: RouteContext): Promise<boolean> {
  const { req, res, path, method } = ctx

  if (path !== '/api/fleet/export' && path !== '/api/fleet/import') return false

  // H1: vault password via header, not query string (avoids access-log / proxy-log / browser-history leakage)
  const vaultPassword = req.headers['x-vault-password'] as string | undefined

  if (path === '/api/fleet/export' && method === 'GET') {
    if (vaultPassword !== undefined && vaultPassword.length < MIN_VAULT_PASSWORD_LEN) {
      json(res, { error: `X-Vault-Password must be at least ${MIN_VAULT_PASSWORD_LEN} characters.` }, 400)
      return true
    }
    try {
      // The export reads skill directories; it waits for an assign's copy still running.
      const exported: ExportedFleet = await serializeSkillsDir(() => exportFleet({ vaultPassword: vaultPassword || undefined }))
      const buf = Buffer.from(exported.data)
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="fleet-export-${exported.exportedAt.slice(0, 10)}.json"`,
        'Content-Length': buf.byteLength,
      })
      res.end(buf)
    } catch (err: any) {
      if (err instanceof UserFacingError) {
        json(res, { error: err.message }, 400)
      } else {
        logger.error({ err: err.message }, 'Fleet export failed')
        json(res, { error: `Export hiba: ${err.message}` }, 500)
      }
    }
    return true
  }

  if (path === '/api/fleet/import' && method === 'POST') {
    const apply = ctx.url.searchParams.get('apply') === 'true'

    // Refuse before anything else: no body read, no password check, no importFleet.
    if (apply && !isFleetImportApplyEnabled()) {
      logger.warn(
        { caller: callerLabel(req), at: new Date().toISOString() },
        'Fleet import apply refused: disabled on this install',
      )
      json(res, { error: `Fleet import (apply=true) ki van kapcsolva ezen a telepítésen (${FLEET_IMPORT_APPLY_ENV}).` }, 403)
      return true
    }

    // Card 24e137ef: applying overwrites personas, settings and hooks of every agent;
    // gated before the body is read. The dry-run preview stays open.
    const gated = apply && execGateApplies(ctx.auth, req)
    if (gated && !admitCodeExecAdmin(ctx, 'fleet.import')) return true

    // M1: check vault password length for import side too
    if (vaultPassword !== undefined && vaultPassword.length < MIN_VAULT_PASSWORD_LEN) {
      json(res, { error: `X-Vault-Password must be at least ${MIN_VAULT_PASSWORD_LEN} characters.` }, 400)
      return true
    }

    let rawBody: string
    try {
      const buf = await readBody(req)
      rawBody = buf.toString()
    } catch (err: any) {
      json(res, { error: `Kérés olvasási hiba: ${err.message}` }, 400)
      return true
    }

    // importFleet handles JSON parse (and encrypted blob detection) internally
    try {
      // The import writes skill directories; it waits for an export's zip or an assign's copy still running.
      const trail = codeExecAuditTrail(gated, 'fleet.import', ctx.auth)
      if (apply) trail.start('fleet')
      let result: Awaited<ReturnType<typeof importFleet>>
      try {
        result = await serializeSkillsDir(() => importFleet(rawBody, { vaultPassword: vaultPassword || undefined, apply }))
        // Card 24e137ef D4: importFleet never writes a new agent's settings.json from
        // the package (result.imported.newAgents[].droppedSettings lists the dropped
        // key names); it comes from the default profile, exactly as in creation.
        if ('ok' in result) {
          for (const a of result.imported.newAgents) writeAgentSettingsFromProfile(a.name, loadProfileTemplate('default'))
        }
      } catch (err) {
        trail.failed(err)
        throw err
      }
      trail.ok()
      if ('dryRun' in result && result.errors.length > 0) {
        json(res, result, 400)
      } else {
        json(res, result, 200)
      }
    } catch (err: any) {
      logger.error({ err: err.message }, 'Fleet import failed')
      json(res, { error: `Import hiba: ${err.message}` }, 500)
    }
    return true
  }

  return false
}

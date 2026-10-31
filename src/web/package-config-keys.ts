import { readFileSync } from 'node:fs'

// Card 51538ebc BD2: agent-config keys a package (bundle or fleet export) never
// chooses. The privilege-bearing ones (securityProfile, claudePlan, capabilities)
// and the machine-specific ones (claudeConfigDir, oauthTokenFile, remoteHost,
// remoteWorkdir: login root, setup-token file, ssh target) stay what the local
// install decided. ONE list for both import paths.
export const PACKAGE_UNTRUSTED_CONFIG_KEYS = [
  'securityProfile',
  'claudePlan',
  'capabilities',
  'claudeConfigDir',
  'oauthTokenFile',
  'remoteHost',
  'remoteWorkdir',
] as const

// Returns the imported config with every PACKAGE_UNTRUSTED_CONFIG_KEYS entry
// replaced by the EXISTING config's value (absent stays absent). Without an
// existing config (new agent) the keys are simply dropped. Pure.
export function applyKeptConfigKeys(
  imported: Record<string, unknown>,
  existing: Record<string, unknown> | null,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...imported }
  for (const key of PACKAGE_UNTRUSTED_CONFIG_KEYS) {
    delete out[key]
    if (existing && Object.prototype.hasOwnProperty.call(existing, key)) out[key] = existing[key]
  }
  return out
}

// Reads an existing agent-config.json for applyKeptConfigKeys. null when the
// file is missing, unreadable or not a plain object (nothing to keep).
export function readExistingConfigForKeep(path: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8'))
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch { return null }
}

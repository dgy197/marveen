import { getSecret } from './vault.js'
import { isPermissionBotVaultId, PERMISSION_BOT_VAULT_ID } from './permission-bot-vault.js'
import { logger } from '../logger.js'

// Card 8e9f4670 (N2): the Vault read an agent launch does on behalf of a provider config
// (custom-provider vaultKey). The permission bot's token is never injected into an agent's
// env: a locked id is warned about (id only, never a value) and answered like a missing
// key, so the callers' existing "key not found" branch stops the launch.
export function readProviderSecret(id: string): string | null {
  if (isPermissionBotVaultId(id)) {
    logger.warn({ event: 'provider-secret-refused', vaultSecretId: PERMISSION_BOT_VAULT_ID },
      'vault: the permission bot token is not injected into an agent environment')
    return null
  }
  return getSecret(id)
}

export * from './constants.js'
export * from './schemas.js'

import { MANAGEMENT_API_PREFIX } from './constants.js'

const crudPermissions = (resource) =>
  Object.freeze({
    read: `read:${resource}`,
    write: `write:${resource}`,
    update: `update:${resource}`,
    delete: `delete:${resource}`
  })

export const MANAGEMENT_PERMISSIONS = Object.freeze({
  customDomains: crudPermissions('custom_domains')
})

export const MANAGEMENT_SCOPE_DESCRIPTIONS = Object.freeze({
  'read:custom_domains': 'Read Custom Domains',
  'write:custom_domains': 'Add Custom Domains',
  'update:custom_domains': 'Check and Reissue Custom Domain Challenges',
  'delete:custom_domains': 'Remove Custom Domains'
})

export const MANAGEMENT_OPERATIONS = Object.freeze({
  listCustomDomains: operation('GET', '/custom-domains', MANAGEMENT_PERMISSIONS.customDomains.read),
  createCustomDomain: operation(
    'POST',
    '/custom-domains',
    MANAGEMENT_PERMISSIONS.customDomains.write
  ),
  getCustomDomain: operation(
    'GET',
    '/custom-domains/{id}',
    MANAGEMENT_PERMISSIONS.customDomains.read
  ),
  deleteCustomDomain: operation(
    'DELETE',
    '/custom-domains/{id}',
    MANAGEMENT_PERMISSIONS.customDomains.delete
  ),
  createCustomDomainVerificationCheck: operation(
    'POST',
    '/custom-domains/{id}/verification-checks',
    MANAGEMENT_PERMISSIONS.customDomains.update
  ),
  reissueCustomDomainChallenge: operation(
    'POST',
    '/custom-domains/{id}/challenge',
    MANAGEMENT_PERMISSIONS.customDomains.update
  )
})

export function managementApiResource(issuer) {
  return `${new URL(issuer).origin}${MANAGEMENT_API_PREFIX}`
}

export function managementApiUrl(issuer, operationId, parameters = {}) {
  const operationDefinition = MANAGEMENT_OPERATIONS[operationId]
  if (!operationDefinition) {
    throw new TypeError(`Unknown management API operation: ${operationId}`)
  }

  const path = operationDefinition.path.replaceAll(/\{([^}]+)\}/g, (_, name) => {
    if (parameters[name] === undefined) {
      throw new TypeError(`Missing parameter "${name}" for ${operationId}`)
    }
    return encodeURIComponent(parameters[name])
  })

  return `${managementApiResource(issuer)}${path}`
}

function operation(method, path, permission, documented = true, implemented = true) {
  return Object.freeze({ method, path, permission, documented, implemented })
}

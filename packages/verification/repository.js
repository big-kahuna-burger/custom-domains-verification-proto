export const CUSTOM_DOMAIN_STATES = Object.freeze([
  'pending',
  'verified',
  'active',
  'verification_lost',
  'failed',
  'removed'
])

const CUSTOM_DOMAIN_REPOSITORY_METHODS = Object.freeze([
  'create',
  'findById',
  'list',
  'recordChallengeCheck',
  'rotateChallenge',
  'verifyChallenge',
  'transition'
])

// Persistence port for the identity provider's custom domains. Consumers inject their adapter;
// this package never imports a persistence implementation or creates a database connection.
export function assertCustomDomainRepository(repository) {
  for (const method of CUSTOM_DOMAIN_REPOSITORY_METHODS) {
    if (typeof repository?.[method] !== 'function') {
      throw new TypeError(`custom domain repository must implement ${method}()`)
    }
  }
  return repository
}

export const CUSTOM_DOMAIN_CONFLICTS = Object.freeze({
  HOST_TAKEN: 'host-taken',
  DOMAIN_LIMIT_REACHED: 'domain-limit-reached'
})

// Adapters throw this from create() when storage rejects a domain: the host is already claimed by
// a domain that is not removed, or the provider already holds the maximum number of domains.
export class CustomDomainConflictError extends Error {
  constructor(code, options) {
    super(`custom domain conflict: ${code}`, options)
    this.name = 'CustomDomainConflictError'
    this.code = code
  }
}

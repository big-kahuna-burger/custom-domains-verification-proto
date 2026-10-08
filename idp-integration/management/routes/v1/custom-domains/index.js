import {
  CUSTOM_DOMAIN_ERRORS,
  MANAGEMENT_ERRORS,
  MANAGEMENT_PERMISSIONS,
  createCustomDomainSchema,
  customDomainParamsSchema,
  customDomainSchema,
  customDomainVerificationCheckSchema,
  customDomainWithChallengeSchema
} from '@custom-domains/contract'
import { CUSTOM_DOMAIN_CONFLICTS } from '@custom-domains/verification'
import { customDomainChallengeDTO, customDomainDTO } from '../../../dtos.js'

const permissions = MANAGEMENT_PERMISSIONS.customDomains
const CHECK_WINDOW_MILLISECONDS = 60_000
const CHECKS_PER_DOMAIN = 1
const CHECKS_PER_PROVIDER = 10
const VERIFIED_STATES = new Set(['verified', 'active'])

const conflictErrors = new Map([
  [CUSTOM_DOMAIN_CONFLICTS.HOST_TAKEN, CUSTOM_DOMAIN_ERRORS.hostTaken],
  [CUSTOM_DOMAIN_CONFLICTS.DOMAIN_LIMIT_REACHED, CUSTOM_DOMAIN_ERRORS.domainLimitReached]
])

export default async function customDomainsRouter(fastify, opts) {
  const management = opts.customDomains
  if (!management) throw new Error('custom domain routes require customDomains from assembly')
  const { repository, verification, normalizeHost, displayHost } = management
  // Assembly injects the actor classifier, as it does for the security audit: autoloaded routes
  // must not brand-check principals against their own copy of the principal contract.
  const { managementActorType } = opts
  if (typeof managementActorType !== 'function') {
    throw new Error('custom domain routes require managementActorType from assembly')
  }
  const actorTypeOf = (request) =>
    managementActorType(request, (reason) =>
      request.log.warn({ reason }, 'management principal rejected')
    )
  const rateLimit = opts.repositories?.rateLimit
  if (typeof rateLimit?.increment !== 'function') {
    throw new Error('custom domain routes require the rate limit counter from assembly')
  }

  const toDTO = (domain) => customDomainDTO(domain, displayHost)
  // Domains belong to this identity provider, so the token's scopes are the whole decision.
  const scoped = (permission) => ({ onRequest: fastify.requireScopes(permission) })
  const params = { params: customDomainParamsSchema }
  // Response schemas also strip anything the DTOs do not name.
  const domainList = { type: 'array', items: customDomainSchema }

  fastify.get(
    '/',
    { ...scoped(permissions.read), schema: { response: { 200: domainList } } },
    listDomains
  )
  fastify.post(
    '/',
    {
      ...scoped(permissions.write),
      schema: { body: createCustomDomainSchema, response: { 201: customDomainWithChallengeSchema } }
    },
    addDomain
  )
  fastify.get(
    '/:id',
    {
      ...scoped(permissions.read),
      schema: { ...params, response: { 200: customDomainSchema } }
    },
    getDomain
  )
  fastify.delete('/:id', { ...scoped(permissions.delete), schema: params }, removeDomain)
  fastify.post(
    '/:id/verification-checks',
    {
      ...scoped(permissions.update),
      schema: { ...params, response: { 200: customDomainVerificationCheckSchema } }
    },
    checkDomain
  )
  fastify.post(
    '/:id/challenge',
    {
      ...scoped(permissions.update),
      schema: { ...params, response: { 200: customDomainWithChallengeSchema } }
    },
    reissue
  )

  async function listDomains() {
    const domains = await repository.list()
    return domains.filter((domain) => domain.state !== 'removed').map(toDTO)
  }

  async function addDomain(request, reply) {
    const normalized = normalizeHost(request.body.host)
    if (!normalized.ok) {
      return sendError(reply, CUSTOM_DOMAIN_ERRORS.invalidHost, { reason: normalized.reason })
    }

    let issued
    try {
      issued = await verification.issue({ host: normalized.host })
    } catch (error) {
      // Matched by name and code, not instanceof: route modules can load a separate copy of the
      // package from the adapter that threw.
      const conflict = error?.name === 'CustomDomainConflictError' && conflictErrors.get(error.code)
      if (conflict) return sendError(reply, conflict)
      throw error
    }

    await auditDomain(request, 'custom_domain.added', issued.domain)
    return reply.code(201).send({
      domain: toDTO(issued.domain),
      challenge: customDomainChallengeDTO(issued.challenge)
    })
  }

  async function getDomain(request, reply) {
    const domain = await findExisting(request)
    if (!domain) return notFound(reply)
    return toDTO(domain)
  }

  async function removeDomain(request, reply) {
    const domain = await findExisting(request)
    if (!domain) return notFound(reply)
    const removed = await repository.transition({ id: domain.id, state: 'removed' })
    if (!removed) return notFound(reply)
    await auditDomain(request, 'custom_domain.removed', removed)
    return reply.code(204).send()
  }

  async function checkDomain(request, reply) {
    if (!management.checksAvailable) {
      return reply.code(503).send({ error: MANAGEMENT_ERRORS.serviceUnavailable.error })
    }

    // The provider window counts every attempt, including unknown IDs; the domain window only
    // counts domains that exist, so unknown IDs stay indistinguishable from missing ones.
    const providerWindow = await rateLimit.increment(
      'custom-domain-check:provider',
      CHECK_WINDOW_MILLISECONDS
    )
    if (providerWindow.current > CHECKS_PER_PROVIDER) return rateLimited(reply, providerWindow)

    const domain = await findExisting(request)
    if (!domain) return notFound(reply)

    const domainWindow = await rateLimit.increment(
      `custom-domain-check:domain:${domain.id}`,
      CHECK_WINDOW_MILLISECONDS
    )
    if (domainWindow.current > CHECKS_PER_DOMAIN) return rateLimited(reply, domainWindow)

    const result = await verification.check({ id: domain.id })
    if (!result || result.domain?.state === 'removed') return notFound(reply)

    if (result.verified) {
      await auditDomain(request, 'custom_domain.verified', result.domain)
      return { verified: true, retryable: false, domain: toDTO(result.domain) }
    }
    // Checking a domain that is already verified reports its standing, not a failure.
    if (VERIFIED_STATES.has(result.domain.state)) {
      return { verified: true, retryable: false, domain: toDTO(result.domain) }
    }
    return {
      verified: false,
      reason: result.reason,
      retryable: result.retryable,
      domain: toDTO(result.domain)
    }
  }

  async function reissue(request, reply) {
    const domain = await findExisting(request)
    if (!domain) return notFound(reply)
    const issued = await verification.reissue({ id: domain.id })
    if (!issued) return notFound(reply)
    await auditDomain(request, 'custom_domain.challenge_reissued', issued.domain)
    return {
      domain: toDTO(issued.domain),
      challenge: customDomainChallengeDTO(issued.challenge)
    }
  }

  // Missing and removed domains both read as absent.
  async function findExisting(request) {
    const domain = await repository.findById(request.params.id)
    return domain && domain.state !== 'removed' ? domain : null
  }

  function auditDomain(request, event, domain) {
    return fastify.audit(request, {
      event,
      outcome: 'success',
      actorType: actorTypeOf(request),
      actorId: request.joseResult?.payload?.sub,
      targetType: 'custom_domain',
      targetId: domain.id,
      targetState: domain.state
    })
  }
}

function notFound(reply) {
  return reply.code(404).send({ error: MANAGEMENT_ERRORS.notFound.error })
}

function rateLimited(reply, window) {
  reply.header('retry-after', String(Math.max(1, Math.ceil(window.ttl / 1000))))
  return sendError(reply, CUSTOM_DOMAIN_ERRORS.rateLimited)
}

function sendError(reply, { statusCode, error, code }, extra = {}) {
  return reply.code(statusCode).send({ error, code, ...extra })
}

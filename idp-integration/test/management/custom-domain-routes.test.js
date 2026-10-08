import Fastify from 'fastify'
import { MANAGEMENT_API_PREFIX } from '@custom-domains/contract'
import { beforeEach, describe, expect, test } from 'vitest'
import { createCustomDomainManagement } from '../../management/custom-domains.js'
import { createInMemoryDnsLookup } from '../../management/dns-lookup.js'
import {
  managementActorType,
  principalFromVerifiedToken
} from '../../management/principal-contract.js'
import customDomainsRouter from '../../management/routes/v1/custom-domains/index.js'
import {
  createInMemoryCustomDomainRepository,
  createInMemoryRateLimitCounter
} from '../fixtures/custom-domains.js'

const ALL_SCOPES =
  'read:custom_domains write:custom_domains update:custom_domains delete:custom_domains'
const BASE = `${MANAGEMENT_API_PREFIX}/custom-domains`
const ISSUER = 'https://id.f0.dev/oidc'

// Bearer value → verified token payload. Stands in for JWT verification; the scope check runs the
// same way the real plugin runs it.
const TOKENS = {
  admin: { sub: 'admin-a', client_id: 'web', scope: ALL_SCOPES },
  'read-only': { sub: 'admin-a', client_id: 'web', scope: 'read:custom_domains' },
  unscoped: { sub: 'admin-a', client_id: 'web', scope: '' },
  // A token that names a retired tenant claim: it carries no authority of its own.
  'claims-tenant': { sub: 'admin-a', client_id: 'web', scope: ALL_SCOPES, tenant_id: 'tenant-b' }
}

async function buildApp({ dnsLookup, zone = {} } = {}) {
  const repository = createInMemoryCustomDomainRepository()
  const rateLimit = createInMemoryRateLimitCounter()
  const audits = []
  const app = Fastify()
  app.decorate('audit', async (_request, event) => {
    audits.push(event)
  })
  app.decorate('requireScopes', (...required) => async (request, reply) => {
    const token = request.headers.authorization?.split(' ')[1]
    const payload = TOKENS[token]
    if (!payload) return reply.code(401).send({ error: 'Unauthorized' })
    request.joseResult = { payload: { iss: ISSUER, ...payload } }
    const { principal } = principalFromVerifiedToken(request.joseResult.payload)
    if (principal !== undefined) request.managementPrincipal = principal
    const granted = new Set(payload.scope.split(' '))
    if (!required.every((scope) => granted.has(scope))) {
      return reply.code(403).send({ error: 'Forbidden' })
    }
  })
  const customDomains = createCustomDomainManagement({
    repository,
    identityProviderHost: 'id.f0.dev',
    dnsLookup: dnsLookup === null ? undefined : (dnsLookup ?? createInMemoryDnsLookup({ zone }))
  })
  await app.register(customDomainsRouter, {
    prefix: BASE,
    customDomains,
    managementActorType,
    repositories: { rateLimit }
  })
  await app.ready()
  return { app, repository, rateLimit, audits, zone }
}

function call(app, token, method, path = '', body) {
  return app.inject({
    method,
    url: `${BASE}${path}`,
    headers: token ? { authorization: `Bearer ${token}` } : {},
    ...(body === undefined ? {} : { payload: body })
  })
}

async function add(app, token, host) {
  const response = await call(app, token, 'POST', '', { host })
  expect(response.statusCode, response.body).toBe(201)
  return response.json()
}

describe('custom domain management routes', () => {
  let ctx
  beforeEach(async () => {
    ctx = await buildApp()
  })

  test('add returns 201 with the TXT instruction once; reads never return it', async () => {
    const created = await add(ctx.app, 'admin', 'Login.Attest.ME')

    expect(created.domain).toMatchObject({
      host: 'login.attest.me',
      displayHost: 'login.attest.me',
      state: 'pending',
      lastCheckedAt: null,
      verifiedAt: null,
      lastFailureReason: null
    })
    expect(created.challenge).toMatchObject({
      recordName: '_f0-challenge.login.attest.me',
      recordType: 'TXT'
    })
    expect(created.challenge.recordValue.startsWith('f0-domain-verification=')).toBe(true)

    const stored = ctx.repository.records.get(created.domain.id)
    expect(JSON.stringify(stored)).not.toContain(created.challenge.recordValue)

    for (const response of [
      await call(ctx.app, 'admin', 'GET'),
      await call(ctx.app, 'admin', 'GET', `/${created.domain.id}`)
    ]) {
      expect(response.statusCode).toBe(200)
      expect(response.body).not.toContain(created.challenge.recordValue)
      expect(response.body).not.toContain(stored.challengeHash)
    }
    expect(JSON.stringify(ctx.audits)).not.toContain(created.challenge.recordValue)
    expect(ctx.audits.at(-1)).toMatchObject({
      event: 'custom_domain.added',
      actorType: 'account',
      targetType: 'custom_domain',
      targetId: created.domain.id,
      targetState: 'pending'
    })
    expect(ctx.audits.at(-1)).not.toHaveProperty('targetTenantId')
  })

  test('returns the Unicode display host for an IDN', async () => {
    const created = await add(ctx.app, 'admin', 'bücher.attest.me')
    expect(created.domain.host).toBe('xn--bcher-kva.attest.me')
    expect(created.domain.displayHost).toBe('bücher.attest.me')
  })

  test('rejects invalid hosts with a stable code and reason, without a row', async () => {
    for (const [host, reason] of [
      ['*.attest.me', 'wildcard'],
      ['203.0.113.7', 'ip-literal'],
      ['login.id.f0.dev', 'identity-provider-domain'],
      ['co.uk', 'public-suffix']
    ]) {
      const response = await call(ctx.app, 'admin', 'POST', '', { host })
      expect(response.statusCode, host).toBe(400)
      expect(response.json()).toEqual({ error: 'Bad Request', code: 'invalid_host', reason })
    }
    expect(ctx.repository.records.size).toBe(0)
  })

  test('ignores unknown body properties, including a tenant identifier', async () => {
    const response = await call(ctx.app, 'claims-tenant', 'POST', '', {
      host: 'login.attest.me',
      tenantId: 'tenant-b'
    })
    expect(response.statusCode).toBe(201)
    expect(ctx.repository.records.get(response.json().domain.id)).not.toHaveProperty('tenantId')
    expect(response.body).not.toContain('tenant-b')
  })

  test('duplicate host and the domain limit answer 409 with distinct codes', async () => {
    await add(ctx.app, 'admin', 'login.attest.me')
    const duplicate = await call(ctx.app, 'admin', 'POST', '', { host: 'login.attest.me' })
    expect(duplicate.statusCode).toBe(409)
    expect(duplicate.json()).toEqual({ error: 'Conflict', code: 'host_taken' })

    for (let index = 1; index < 10; index += 1) await add(ctx.app, 'admin', `d${index}.attest.me`)
    const eleventh = await call(ctx.app, 'admin', 'POST', '', { host: 'd10.attest.me' })
    expect(eleventh.statusCode).toBe(409)
    expect(eleventh.json()).toEqual({ error: 'Conflict', code: 'domain_limit_reached' })
    expect(ctx.repository.records.size).toBe(10)
  })

  test('missing and removed domains are indistinguishable 404s', async () => {
    const created = await add(ctx.app, 'admin', 'login.attest.me')
    const id = created.domain.id
    const missing = '00000000-0000-4000-8000-000000000000'

    for (const path of [
      `/${missing}`,
      `/${missing}/challenge`,
      `/${missing}/verification-checks`
    ]) {
      const method = path.endsWith(missing) ? 'GET' : 'POST'
      const response = await call(ctx.app, 'admin', method, path)
      expect(response.statusCode, path).toBe(404)
      expect(response.json()).toEqual({ error: 'Not Found' })
    }

    const removed = await call(ctx.app, 'admin', 'DELETE', `/${id}`)
    expect(removed.statusCode).toBe(204)
    expect(ctx.audits.at(-1)).toMatchObject({
      event: 'custom_domain.removed',
      targetState: 'removed'
    })
    expect((await call(ctx.app, 'admin', 'GET', `/${id}`)).json()).toEqual({ error: 'Not Found' })
    expect((await call(ctx.app, 'admin', 'DELETE', `/${id}`)).statusCode).toBe(404)
    expect((await call(ctx.app, 'admin', 'GET')).json()).toEqual([])

    const malformed = await call(ctx.app, 'admin', 'GET', '/not-a-uuid')
    expect(malformed.statusCode).toBe(400)
  })

  test('a removed host can be added again with a fresh challenge', async () => {
    const first = await add(ctx.app, 'admin', 'login.attest.me')
    await call(ctx.app, 'admin', 'DELETE', `/${first.domain.id}`)
    const second = await add(ctx.app, 'admin', 'login.attest.me')
    expect(second.domain.id).not.toBe(first.domain.id)
    expect(second.challenge.recordValue).not.toBe(first.challenge.recordValue)
  })

  test('verification check verifies a matching TXT record and audits it', async () => {
    const created = await add(ctx.app, 'admin', 'login.attest.me')
    const unpublished = await call(
      ctx.app,
      'admin',
      'POST',
      `/${created.domain.id}/verification-checks`
    )
    expect(unpublished.statusCode).toBe(200)
    expect(unpublished.json()).toMatchObject({
      verified: false,
      reason: 'dns-nxdomain',
      domain: { state: 'pending', lastFailureReason: 'dns-nxdomain' }
    })

    ctx.zone[created.challenge.recordName] = { txt: [created.challenge.recordValue] }
    ctx.rateLimit.windows.clear()
    const verified = await call(
      ctx.app,
      'admin',
      'POST',
      `/${created.domain.id}/verification-checks`
    )
    expect(verified.statusCode).toBe(200)
    expect(verified.json()).toMatchObject({
      verified: true,
      retryable: false,
      domain: { state: 'verified', lastFailureReason: null }
    })
    expect(verified.json().reason).toBeUndefined()
    expect(ctx.audits.at(-1)).toMatchObject({
      event: 'custom_domain.verified',
      targetState: 'verified'
    })

    ctx.rateLimit.windows.clear()
    const again = await call(ctx.app, 'admin', 'POST', `/${created.domain.id}/verification-checks`)
    expect(again.json()).toMatchObject({ verified: true, domain: { state: 'verified' } })
  })

  test('reissue rotates the challenge so the old TXT value stops verifying', async () => {
    const created = await add(ctx.app, 'admin', 'login.attest.me')
    const reissued = await call(ctx.app, 'admin', 'POST', `/${created.domain.id}/challenge`)
    expect(reissued.statusCode).toBe(200)
    const body = reissued.json()
    expect(body.challenge.recordValue).not.toBe(created.challenge.recordValue)
    expect(ctx.audits.at(-1)).toMatchObject({ event: 'custom_domain.challenge_reissued' })

    ctx.zone[created.challenge.recordName] = { txt: [created.challenge.recordValue] }
    const check = await call(ctx.app, 'admin', 'POST', `/${created.domain.id}/verification-checks`)
    expect(check.json()).toMatchObject({ verified: false, reason: 'txt-record-mismatch' })
  })

  test('checks are limited to one per domain and ten per provider per minute', async () => {
    const created = await add(ctx.app, 'admin', 'login.attest.me')
    const path = `/${created.domain.id}/verification-checks`
    expect((await call(ctx.app, 'admin', 'POST', path)).statusCode).toBe(200)

    const limited = await call(ctx.app, 'admin', 'POST', path)
    expect(limited.statusCode).toBe(429)
    expect(limited.headers['retry-after']).toBe('60')
    expect(limited.json()).toEqual({ error: 'Too Many Requests', code: 'rate_limited' })

    const missing = '00000000-0000-4000-8000-000000000000'
    for (let attempt = 3; attempt <= 10; attempt += 1) {
      expect(
        (await call(ctx.app, 'admin', 'POST', `/${missing}/verification-checks`)).statusCode
      ).toBe(404)
    }
    // The eleventh attempt in the window is refused before the domain is looked up at all.
    const providerLimited = await call(ctx.app, 'admin', 'POST', `/${missing}/verification-checks`)
    expect(providerLimited.statusCode).toBe(429)
  })

  test('scopes gate every operation', async () => {
    const created = await add(ctx.app, 'admin', 'login.attest.me')
    expect((await call(ctx.app, 'read-only', 'GET')).statusCode).toBe(200)
    expect((await call(ctx.app, 'read-only', 'POST', '', { host: 'x.attest.me' })).statusCode).toBe(
      403
    )
    expect((await call(ctx.app, 'read-only', 'DELETE', `/${created.domain.id}`)).statusCode).toBe(
      403
    )
    expect(
      (await call(ctx.app, 'read-only', 'POST', `/${created.domain.id}/challenge`)).statusCode
    ).toBe(403)
    expect((await call(ctx.app, 'unscoped', 'GET')).statusCode).toBe(403)
    expect((await call(ctx.app, undefined, 'GET')).statusCode).toBe(401)
  })

  test('checks answer 503 when no DNS resolvers are configured', async () => {
    const withoutDns = await buildApp({ dnsLookup: null })
    const created = await add(withoutDns.app, 'admin', 'login.attest.me')
    const response = await call(
      withoutDns.app,
      'admin',
      'POST',
      `/${created.domain.id}/verification-checks`
    )
    expect(response.statusCode).toBe(503)
    expect(response.json()).toEqual({ error: 'Service Unavailable' })
    expect(withoutDns.rateLimit.windows.size).toBe(0)
  })
})

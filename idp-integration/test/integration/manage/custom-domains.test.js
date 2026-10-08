import { desc, like } from 'drizzle-orm'
import { beforeEach, describe, expect, it } from 'vitest'
import database from '../../../persistence/client.js'
import { auditEvents, customDomains } from '../../../persistence/schema.js'
import { build } from '../helper.js'
import { sign } from '../../sign.js'

const runtimeConfig = {
  issuer: 'http://localhost:9876/oidc',
  cookieSecret: 'test-cookie-secret-at-least-20-bytes',
  managementCorsOrigins: ['http://localhost:3036'],
  dynamicClientRegistrationEnabled: false
}

const DOMAIN_SCOPES =
  'read:custom_domains write:custom_domains update:custom_domains delete:custom_domains'

describe('custom domain management API', () => {
  let app
  let admin
  const bearer = async (subject, scope = DOMAIN_SCOPES) => ({
    authorization: `Bearer ${await sign({ sub: subject, client_id: 'web-client', scope })}`
  })

  beforeEach(async () => {
    app = await build({ runtimeConfig })
    admin = await bearer('admin-a')
    return async () => {
      await app.close()
    }
  })

  const add = (headers, host) =>
    app.inject({ method: 'POST', url: '/manage/v1/custom-domains', headers, payload: { host } })

  const list = (headers) => app.inject({ url: '/manage/v1/custom-domains', headers })

  it('audits a workload token as the service actor', async () => {
    const service = {
      authorization: `Bearer ${await sign({ sub: 'm2m-client', client_id: 'm2m-client' })}`
    }
    expect((await list(service)).statusCode).toBe(200)
    expect((await add(service, 'service.attest.me')).statusCode).toBe(201)
    const [event] = await database
      .select()
      .from(auditEvents)
      .where(like(auditEvents.event, 'custom_domain.%'))
    expect(event.actor).toMatchObject({ type: 'service', id: 'm2m-client' })
    expect(event.target).not.toHaveProperty('tenantId')
  })

  it('answers 403 and writes nothing when the token lacks the scope', async () => {
    const narrowed = await bearer('admin-a', 'read:custom_domains')
    expect((await list(narrowed)).statusCode).toBe(200)
    expect((await add(narrowed, 'narrow.attest.me')).json()).toEqual({ error: 'Forbidden' })
    expect(await database.select().from(customDomains)).toEqual([])

    const denials = await database
      .select()
      .from(auditEvents)
      .where(like(auditEvents.event, 'authorization.management_scope'))
    expect(denials.map((row) => row.reason)).toEqual(['insufficient_scope'])
  })

  it('ignores a tenant claim carried by the token', async () => {
    const claimed = {
      authorization: `Bearer ${await sign({ sub: 'admin-a', client_id: 'web-client', tenant_id: 'tenant-b', scope: DOMAIN_SCOPES })}`
    }
    expect((await add(claimed, 'claim.attest.me')).statusCode).toBe(201)
    const [row] = await database.select().from(customDomains)
    expect(row).not.toHaveProperty('tenantId')
  })

  it('adds, reads and removes a domain through PostgreSQL', async () => {
    const created = await add(admin, 'login.attest.me')
    expect(created.statusCode).toBe(201)
    const { domain, challenge } = created.json()
    expect(domain).toMatchObject({ host: 'login.attest.me', state: 'pending' })
    expect(challenge.recordName).toBe('_f0-challenge.login.attest.me')

    const [row] = await database.select().from(customDomains)
    expect(row).toMatchObject({ id: domain.id, host: 'login.attest.me' })
    expect(row.challengeHash).not.toContain(challenge.recordValue)

    const read = await app.inject({
      url: `/manage/v1/custom-domains/${domain.id}`,
      headers: admin
    })
    expect(read.statusCode).toBe(200)
    expect(read.body).not.toContain(challenge.recordValue)
    expect(read.body).not.toContain(row.challengeHash)

    const removed = await app.inject({
      method: 'DELETE',
      url: `/manage/v1/custom-domains/${domain.id}`,
      headers: admin
    })
    expect(removed.statusCode).toBe(204)
    expect((await list(admin)).json()).toEqual([])

    const events = await database
      .select()
      .from(auditEvents)
      .where(like(auditEvents.event, 'custom_domain.%'))
      .orderBy(desc(auditEvents.occurredAt))
    expect(events.map(({ event }) => event).sort()).toEqual([
      'custom_domain.added',
      'custom_domain.removed'
    ])
    for (const event of events) {
      expect(event.target).toMatchObject({ type: 'custom_domain', id: domain.id })
      expect(JSON.stringify(event)).not.toContain(challenge.recordValue)
      expect(JSON.stringify(event)).not.toContain(row.challengeHash)
    }
  })

  it('maps the active-host index and the domain limit to distinct 409 codes', async () => {
    expect((await add(admin, 'login.attest.me')).statusCode).toBe(201)
    const duplicate = await add(admin, 'login.attest.me')
    expect(duplicate.statusCode).toBe(409)
    expect(duplicate.json()).toEqual({ error: 'Conflict', code: 'host_taken' })

    for (let index = 1; index < 10; index += 1) {
      expect((await add(admin, `d${index}.attest.me`)).statusCode).toBe(201)
    }
    const eleventh = await add(admin, 'd10.attest.me')
    expect(eleventh.statusCode).toBe(409)
    expect(eleventh.json()).toEqual({ error: 'Conflict', code: 'domain_limit_reached' })
  })

  it('answers 503 for checks when no DNS resolvers are configured', async () => {
    const { domain } = (await add(admin, 'login.attest.me')).json()
    const check = await app.inject({
      method: 'POST',
      url: `/manage/v1/custom-domains/${domain.id}/verification-checks`,
      headers: admin
    })
    expect(check.statusCode).toBe(503)
  })
})

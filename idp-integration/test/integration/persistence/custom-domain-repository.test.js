import { CUSTOM_DOMAIN_CONFLICTS } from '@custom-domains/verification'
import { beforeEach, describe, expect, it } from 'vitest'

import { createCustomDomainRepository } from '../../../persistence/custom-domain-repository.js'
import database from '../../../persistence/client.js'
import { resetDatabase } from '../helper.js'

const challengeExpiresAt = new Date('2030-01-01T00:00:00.000Z')

function domainInput(overrides = {}) {
  return {
    host: 'login.example.dev',
    challengeHash: 'a'.repeat(64),
    challengeExpiresAt,
    ...overrides
  }
}

describe('custom domain repository', () => {
  beforeEach(resetDatabase)

  it('stores the verification record and all lifecycle states', async () => {
    const repository = createCustomDomainRepository(database)
    const pending = await repository.create(domainInput())

    expect(pending).toMatchObject({
      host: 'login.example.dev',
      state: 'pending',
      challengeHash: 'a'.repeat(64),
      challengeExpiresAt,
      lastCheckedAt: null,
      verifiedAt: null,
      lastFailureReason: null
    })
    expect(pending).not.toHaveProperty('tenantId')
    expect(pending.createdAt).toBeInstanceOf(Date)
    expect(pending.updatedAt).toBeInstanceOf(Date)
    await expect(repository.findById('00000000-0000-4000-8000-000000000000')).resolves.toBeNull()

    const lastCheckedAt = new Date('2029-12-01T00:00:00.000Z')
    const verifiedAt = new Date('2029-12-01T00:01:00.000Z')
    const states = ['verified', 'active', 'verification_lost', 'failed', 'removed']
    let record = pending
    for (const state of states) {
      record = await repository.transition({
        id: pending.id,
        state,
        lastCheckedAt,
        verifiedAt,
        lastFailureReason: state === 'failed' ? 'dns-timeout' : null
      })
      expect(record.state).toBe(state)
    }

    expect(record).toMatchObject({
      lastCheckedAt,
      verifiedAt,
      lastFailureReason: null
    })
    await expect(repository.list()).resolves.toEqual([record])
  })

  it('keeps a host unique until its record is removed', async () => {
    const repository = createCustomDomainRepository(database)
    const claimed = await repository.create(domainInput())

    await expect(repository.create(domainInput())).rejects.toMatchObject({
      name: 'CustomDomainConflictError',
      code: CUSTOM_DOMAIN_CONFLICTS.HOST_TAKEN
    })

    await repository.transition({ id: claimed.id, state: 'removed' })
    await expect(repository.create(domainInput())).resolves.toMatchObject({ host: claimed.host })
  })

  it('admits exactly ten non-removed domains under concurrent inserts', async () => {
    const repository = createCustomDomainRepository(database)
    const attempts = await Promise.allSettled(
      Array.from({ length: 12 }, (_, index) =>
        repository.create(
          domainInput({
            host: `domain-${index}.example.dev`,
            challengeHash: index.toString(16).padStart(64, '0')
          })
        )
      )
    )

    expect(attempts.filter(({ status }) => status === 'fulfilled')).toHaveLength(10)
    const rejected = attempts.filter(({ status }) => status === 'rejected')
    expect(rejected).toHaveLength(2)
    for (const { reason } of rejected) {
      expect(reason).toMatchObject({
        name: 'CustomDomainConflictError',
        code: CUSTOM_DOMAIN_CONFLICTS.DOMAIN_LIMIT_REACHED
      })
    }
    await expect(repository.list()).resolves.toHaveLength(10)

    const [removed] = await repository.list()
    await repository.transition({ id: removed.id, state: 'removed' })
    await expect(
      repository.create(domainInput({ host: 'replacement.example.dev' }))
    ).resolves.toBeDefined()
  })
})

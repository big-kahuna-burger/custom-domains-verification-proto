import { beforeEach, describe, expect, it } from 'vitest'
import { eq } from 'drizzle-orm'
import { createCustomDomainVerification } from '@custom-domains/verification'

import { createInMemoryDnsLookup } from '../../../management/dns-lookup.js'
import { createCustomDomainRepository } from '../../../persistence/custom-domain-repository.js'
import database from '../../../persistence/client.js'
import { customDomains } from '../../../persistence/schema.js'
import { resetDatabase } from '../helper.js'

const NOW = new Date('2030-01-01T00:00:00.000Z')

describe('custom domain verification persistence', () => {
  beforeEach(resetDatabase)

  it('atomically persists the pending to verified transition', async () => {
    const repository = createCustomDomainRepository(database)
    const issuer = createCustomDomainVerification({
      repository,
      dnsLookup: createInMemoryDnsLookup(),
      now: () => NOW,
      generateRandomBytes: () => Buffer.alloc(32, 3)
    })
    const issued = await issuer.issue({ host: 'login.example.dev' })
    const verifier = createCustomDomainVerification({
      repository,
      dnsLookup: createInMemoryDnsLookup({
        zone: {
          '_f0-challenge.login.example.dev': { txt: [issued.challenge.value] }
        }
      }),
      now: () => NOW
    })

    await expect(verifier.check({ id: issued.domain.id })).resolves.toMatchObject({
      verified: true,
      domain: { state: 'verified' }
    })
    await expect(repository.findById(issued.domain.id)).resolves.toMatchObject({
      state: 'verified',
      lastCheckedAt: NOW,
      verifiedAt: NOW,
      lastFailureReason: null
    })
  })

  it('rejects a verification that waits in PostgreSQL until after expiry', async () => {
    const repository = createCustomDomainRepository(database)
    const challengeExpiresAt = new Date(Date.now() + 1500)
    const pending = await repository.create({
      host: 'expired.example.dev',
      challengeHash: 'a'.repeat(64),
      challengeExpiresAt
    })

    let markLocked
    const locked = new Promise((resolve) => {
      markLocked = resolve
    })
    let releaseLock
    const holdLock = new Promise((resolve) => {
      releaseLock = resolve
    })
    const lockTransaction = database.transaction(async (transaction) => {
      await transaction
        .select({ id: customDomains.id })
        .from(customDomains)
        .where(eq(customDomains.id, pending.id))
        .for('update')
      markLocked()
      await holdLock
    })
    await locked

    const checkedAt = new Date()
    const verification = repository.verifyChallenge({
      id: pending.id,
      challengeHash: pending.challengeHash,
      checkedAt
    })
    await new Promise((resolve) =>
      setTimeout(resolve, Math.max(0, challengeExpiresAt.getTime() - Date.now() + 250))
    )
    releaseLock()
    await lockTransaction

    expect(checkedAt.getTime()).toBeLessThan(challengeExpiresAt.getTime())
    await expect(verification).resolves.toBeNull()
    await expect(repository.findById(pending.id)).resolves.toMatchObject({
      state: 'pending',
      verifiedAt: null
    })
  })
})

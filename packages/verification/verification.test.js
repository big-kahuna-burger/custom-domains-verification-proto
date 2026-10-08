import { describe, expect, it, vi } from 'vitest'

import { DNS_LOOKUP_ERROR_CODES, DnsLookupError } from './dns.js'
import {
  CUSTOM_DOMAIN_CHALLENGE_TTL_MILLISECONDS,
  createCustomDomainVerification
} from './verification.js'

const NOW = new Date('2030-01-01T00:00:00.000Z')

function createInMemoryDnsLookup({ zone = {} } = {}) {
  const entryFor = (host) => {
    const entry = Object.hasOwn(zone, host) ? zone[host] : undefined
    if (!entry) throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.NXDOMAIN)
    return entry
  }
  return {
    async lookupTxt(host) {
      const records = entryFor(host).txt ?? []
      if (records.length === 0) throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.NODATA)
      return records.map((record) => (Array.isArray(record) ? record.join('') : record))
    },
    async lookupCname(host) {
      const records = entryFor(host).cname ?? []
      if (records.length === 0) throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.NODATA)
      return records
    }
  }
}

function createRepositoryFake() {
  let nextId = 1
  const records = new Map()
  const calls = { create: [], verify: [] }
  return {
    calls,
    records,
    async create(input) {
      calls.create.push(input)
      const record = { id: String(nextId++), state: 'pending', ...input }
      records.set(record.id, record)
      return record
    },
    async findById(id) {
      return records.get(id) ?? null
    },
    async list() {
      return [...records.values()]
    },
    async recordChallengeCheck(input) {
      const record = records.get(input.id)
      if (!record || record.state !== 'pending' || record.challengeHash !== input.challengeHash) {
        return null
      }
      Object.assign(record, {
        lastCheckedAt: input.checkedAt,
        lastFailureReason: input.failureReason
      })
      return record
    },
    async rotateChallenge(input) {
      const record = records.get(input.id)
      if (!record || record.state === 'removed') return null
      Object.assign(record, {
        state: 'pending',
        challengeHash: input.challengeHash,
        challengeExpiresAt: input.challengeExpiresAt,
        lastCheckedAt: null,
        verifiedAt: null,
        lastFailureReason: null
      })
      return record
    },
    async verifyChallenge(input) {
      calls.verify.push(input)
      const record = records.get(input.id)
      if (
        !record ||
        record.state !== 'pending' ||
        record.challengeHash !== input.challengeHash ||
        record.challengeExpiresAt <= input.checkedAt
      ) {
        return null
      }
      Object.assign(record, {
        state: 'verified',
        lastCheckedAt: input.checkedAt,
        verifiedAt: input.checkedAt,
        lastFailureReason: null
      })
      return record
    },
    async transition() {}
  }
}

function fixedEntropy(byte) {
  return vi.fn(() => Buffer.alloc(32, byte))
}

function createService({ repository, zone, now = () => NOW, entropy = fixedEntropy(1) }) {
  return createCustomDomainVerification({
    repository,
    dnsLookup: createInMemoryDnsLookup({ zone }),
    now,
    generateRandomBytes: entropy
  })
}

describe('custom domain DNS verification', () => {
  it('issues a reveal-once, seven-day challenge and persists only its bound hash', async () => {
    const repository = createRepositoryFake()
    const entropy = fixedEntropy(7)
    const service = createService({ repository, zone: {}, entropy })

    const issued = await service.issue({ host: 'login.example.dev' })

    expect(entropy).toHaveBeenCalledWith(32)
    expect(issued.challenge).toEqual({
      name: '_f0-challenge.login.example.dev',
      value: `f0-domain-verification=${Buffer.alloc(32, 7).toString('base64url')}`,
      expiresAt: new Date(NOW.getTime() + CUSTOM_DOMAIN_CHALLENGE_TTL_MILLISECONDS)
    })
    expect(repository.calls.create[0].challengeHash).toHaveLength(64)
    expect(
      [...repository.calls.create[0].challengeHash].every((character) =>
        'abcdef0123456789'.includes(character)
      )
    ).toBe(true)
    expect(JSON.stringify(repository.calls.create[0])).not.toContain(issued.challenge.value)
  })

  it('accepts an exact TXT value among unrelated records and moves pending to verified', async () => {
    const repository = createRepositoryFake()
    const issuer = createService({ repository, zone: {} })
    const issued = await issuer.issue({ host: 'login.example.dev' })
    const service = createService({
      repository,
      zone: {
        '_f0-challenge.login.example.dev': {
          txt: ['provider=unrelated', `${issued.challenge.value}-not-exact`, issued.challenge.value]
        }
      }
    })

    const result = await service.check({ id: issued.domain.id })

    expect(result).toMatchObject({ verified: true, domain: { state: 'verified' } })
    expect(result.domain.verifiedAt).toEqual(NOW)
  })

  it('rejects CNAME delegation even when the target publishes the token', async () => {
    const repository = createRepositoryFake()
    const issuer = createService({ repository, zone: {} })
    const issued = await issuer.issue({ host: 'login.example.dev' })
    const service = createService({
      repository,
      zone: {
        '_f0-challenge.login.example.dev': { cname: ['delegated.example.net'] },
        'delegated.example.net': { txt: [issued.challenge.value] }
      }
    })

    await expect(service.check({ id: issued.domain.id })).resolves.toMatchObject({
      verified: false,
      reason: 'cname-not-allowed'
    })
    expect(repository.calls.verify).toHaveLength(0)
  })

  it('does not verify an expired challenge', async () => {
    const repository = createRepositoryFake()
    const issuer = createService({ repository, zone: {} })
    const issued = await issuer.issue({ host: 'login.example.dev' })
    const dnsLookup = {
      lookupCname: vi.fn(),
      lookupTxt: vi.fn()
    }
    const service = createCustomDomainVerification({
      repository,
      dnsLookup,
      now: () => issued.challenge.expiresAt,
      generateRandomBytes: fixedEntropy(2)
    })

    await expect(service.check({ id: issued.domain.id })).resolves.toMatchObject({
      verified: false,
      reason: 'challenge-expired'
    })
    expect(dnsLookup.lookupCname).not.toHaveBeenCalled()
    expect(dnsLookup.lookupTxt).not.toHaveBeenCalled()
  })

  it('does not verify when DNS lookup crosses the expiry boundary', async () => {
    const repository = createRepositoryFake()
    const issuer = createService({ repository, zone: {} })
    const issued = await issuer.issue({ host: 'login.example.dev' })
    const dnsFake = createInMemoryDnsLookup({
      zone: {
        '_f0-challenge.login.example.dev': { txt: [issued.challenge.value] }
      }
    })
    let currentTime = new Date(issued.challenge.expiresAt.getTime() - 1)
    const dnsLookup = {
      lookupCname: (host) => dnsFake.lookupCname(host),
      async lookupTxt(host) {
        const records = await dnsFake.lookupTxt(host)
        currentTime = issued.challenge.expiresAt
        return records
      }
    }
    const service = createCustomDomainVerification({
      repository,
      dnsLookup,
      now: () => currentTime
    })

    await expect(service.check({ id: issued.domain.id })).resolves.toMatchObject({
      verified: false,
      reason: 'challenge-expired'
    })
    expect(repository.calls.verify).toHaveLength(0)
  })

  it('reissuing rotates the token so the old TXT value cannot verify', async () => {
    const repository = createRepositoryFake()
    const entropy = vi
      .fn()
      .mockReturnValueOnce(Buffer.alloc(32, 1))
      .mockReturnValueOnce(Buffer.alloc(32, 2))
    const issuer = createService({ repository, zone: {}, entropy })
    const first = await issuer.issue({ host: 'login.example.dev' })
    const second = await issuer.reissue({ id: first.domain.id })
    expect(second.challenge.value).not.toBe(first.challenge.value)

    const oldRecord = createService({
      repository,
      zone: { '_f0-challenge.login.example.dev': { txt: [first.challenge.value] } }
    })
    await expect(oldRecord.check({ id: first.domain.id })).resolves.toMatchObject({
      verified: false,
      reason: 'txt-record-mismatch'
    })
  })

  it('binds the same random token to the domain it was issued for', async () => {
    const repository = createRepositoryFake()
    const first = await createService({
      repository,
      zone: {},
      entropy: fixedEntropy(9)
    }).issue({ host: 'one.example.dev' })
    const second = await createService({
      repository,
      zone: {},
      entropy: fixedEntropy(9)
    }).issue({ host: 'two.example.dev' })

    expect(first.challenge.value).toBe(second.challenge.value)
    expect(first.domain.challengeHash).not.toBe(second.domain.challengeHash)
  })

  it('requires a fresh proof when a removed domain is added again', async () => {
    const repository = createRepositoryFake()
    const first = await createService({
      repository,
      zone: {},
      entropy: fixedEntropy(4)
    }).issue({ host: 'login.example.dev' })
    first.domain.state = 'removed'
    const second = await createService({
      repository,
      zone: {},
      entropy: fixedEntropy(5)
    }).issue({ host: 'login.example.dev' })

    const staleProof = createService({
      repository,
      zone: { '_f0-challenge.login.example.dev': { txt: [first.challenge.value] } }
    })
    await expect(staleProof.check({ id: second.domain.id })).resolves.toMatchObject({
      verified: false,
      reason: 'txt-record-mismatch'
    })
  })
})

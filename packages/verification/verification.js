import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

import { DNS_LOOKUP_ERROR_CODES, DnsLookupError } from './dns.js'
import { assertCustomDomainRepository } from './repository.js'

export const CUSTOM_DOMAIN_CHALLENGE_LABEL = '_f0-challenge'
export const CUSTOM_DOMAIN_CHALLENGE_PREFIX = 'f0-domain-verification='
export const CUSTOM_DOMAIN_CHALLENGE_TTL_MILLISECONDS = 7 * 24 * 60 * 60 * 1000

export const CUSTOM_DOMAIN_VERIFICATION_FAILURES = Object.freeze({
  EXPIRED: 'challenge-expired',
  CNAME_NOT_ALLOWED: 'cname-not-allowed',
  RECORD_MISMATCH: 'txt-record-mismatch',
  NOT_PENDING: 'domain-not-pending',
  CHALLENGE_CHANGED: 'challenge-changed'
})

const RANDOM_BYTES = 32
const MINIMUM_RANDOM_BYTES = 16

export function createCustomDomainVerification({
  repository,
  dnsLookup,
  now = () => new Date(),
  generateRandomBytes = randomBytes
}) {
  assertCustomDomainRepository(repository)
  if (typeof dnsLookup?.lookupTxt !== 'function' || typeof dnsLookup?.lookupCname !== 'function') {
    throw new TypeError('custom domain verification requires a DNS lookup port')
  }

  async function issue({ host }) {
    const challenge = createChallenge(host, now, generateRandomBytes)
    const domain = await repository.create({
      host,
      challengeHash: challenge.hash,
      challengeExpiresAt: challenge.expiresAt
    })
    return reveal(domain, challenge)
  }

  async function reissue({ id }) {
    const existing = await repository.findById(id)
    if (!existing || existing.state === 'removed') return null

    const challenge = createChallenge(existing.host, now, generateRandomBytes)
    const domain = await repository.rotateChallenge({
      id,
      challengeHash: challenge.hash,
      challengeExpiresAt: challenge.expiresAt
    })
    return domain ? reveal(domain, challenge) : null
  }

  async function check({ id }) {
    const domain = await repository.findById(id)
    if (!domain) return null
    if (domain.state !== 'pending') {
      return failed(domain, CUSTOM_DOMAIN_VERIFICATION_FAILURES.NOT_PENDING)
    }

    let checkedAt = currentDate(now)
    if (domain.challengeExpiresAt <= checkedAt) {
      return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.EXPIRED)
    }

    const name = challengeName(domain.host)
    try {
      await dnsLookup.lookupCname(name)
      checkedAt = currentDate(now)
      if (domain.challengeExpiresAt <= checkedAt) {
        return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.EXPIRED)
      }
      return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.CNAME_NOT_ALLOWED)
    } catch (error) {
      if (!isDnsError(error, DNS_LOOKUP_ERROR_CODES.NODATA)) {
        return handleDnsFailure(domain, currentDate(now), error)
      }
    }

    checkedAt = currentDate(now)
    if (domain.challengeExpiresAt <= checkedAt) {
      return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.EXPIRED)
    }

    let records
    try {
      records = await dnsLookup.lookupTxt(name)
    } catch (error) {
      return handleDnsFailure(domain, currentDate(now), error)
    }

    checkedAt = currentDate(now)
    if (domain.challengeExpiresAt <= checkedAt) {
      return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.EXPIRED)
    }

    const matched = records.some((value) => challengeMatches(domain, value))
    if (!matched) {
      return recordFailure(domain, checkedAt, CUSTOM_DOMAIN_VERIFICATION_FAILURES.RECORD_MISMATCH)
    }

    const verified = await repository.verifyChallenge({
      id,
      challengeHash: domain.challengeHash,
      checkedAt
    })
    if (verified) return { verified: true, domain: verified }

    const current = await repository.findById(id)
    return failed(current ?? domain, CUSTOM_DOMAIN_VERIFICATION_FAILURES.CHALLENGE_CHANGED)
  }

  async function handleDnsFailure(domain, checkedAt, error) {
    if (!(error instanceof DnsLookupError)) throw error
    const reason = `dns-${error.code.toLowerCase()}`
    return recordFailure(domain, checkedAt, reason, error.retryable)
  }

  async function recordFailure(domain, checkedAt, reason, retryable = false) {
    const current = await repository.recordChallengeCheck({
      id: domain.id,
      challengeHash: domain.challengeHash,
      checkedAt,
      failureReason: reason
    })
    if (!current) {
      const latest = await repository.findById(domain.id)
      return failed(latest ?? domain, CUSTOM_DOMAIN_VERIFICATION_FAILURES.CHALLENGE_CHANGED, false)
    }
    return failed(current, reason, retryable)
  }

  return Object.freeze({ issue, reissue, check })
}

function createChallenge(host, now, generateRandomBytes) {
  const entropy = generateRandomBytes(RANDOM_BYTES)
  if (!Buffer.isBuffer(entropy) || entropy.byteLength < MINIMUM_RANDOM_BYTES) {
    throw new TypeError('custom domain challenge requires at least 128 random bits')
  }
  const value = `${CUSTOM_DOMAIN_CHALLENGE_PREFIX}${entropy.toString('base64url')}`
  const issuedAt = currentDate(now)
  const expiresAt = new Date(issuedAt.getTime() + CUSTOM_DOMAIN_CHALLENGE_TTL_MILLISECONDS)
  return { value, hash: challengeHash(host, value), expiresAt }
}

function challengeName(host) {
  return `${CUSTOM_DOMAIN_CHALLENGE_LABEL}.${host}`
}

function challengeHash(host, value) {
  return createHash('sha256').update(host).update('\0').update(value).digest('hex')
}

function challengeMatches(domain, value) {
  if (!value.startsWith(CUSTOM_DOMAIN_CHALLENGE_PREFIX)) return false
  const stored = Buffer.from(domain.challengeHash, 'hex')
  const candidate = Buffer.from(challengeHash(domain.host, value), 'hex')
  return stored.byteLength === candidate.byteLength && timingSafeEqual(stored, candidate)
}

function currentDate(now) {
  const date = new Date(now())
  if (Number.isNaN(date.getTime()))
    throw new TypeError('custom domain verification requires a clock')
  return date
}

function reveal(domain, challenge) {
  return {
    domain,
    challenge: {
      name: challengeName(domain.host),
      value: challenge.value,
      expiresAt: challenge.expiresAt
    }
  }
}

function failed(domain, reason, retryable = false) {
  return { verified: false, reason, retryable, domain }
}

function isDnsError(error, code) {
  return error instanceof DnsLookupError && error.code === code
}

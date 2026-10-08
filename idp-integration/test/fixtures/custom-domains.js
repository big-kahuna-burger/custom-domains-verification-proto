import { randomUUID } from 'node:crypto'
import {
  CUSTOM_DOMAIN_CONFLICTS,
  CustomDomainConflictError,
  assertCustomDomainRepository
} from '@custom-domains/verification'

/**
 * In-memory custom-domain repository for tests. Mirrors the PostgreSQL adapter's guards: one
 * active domain per host and at most `limit` active domains in the whole store.
 */
export function createInMemoryCustomDomainRepository({ limit = 10, clock = () => new Date() } = {}) {
  const records = new Map()
  const active = (record) => record.state !== 'removed'
  const touch = (record, changes) => Object.assign(record, changes, { updatedAt: clock() })

  return assertCustomDomainRepository({
    records,
    async create({ host, challengeHash, challengeExpiresAt }) {
      const all = [...records.values()].filter(active)
      if (all.some((record) => record.host === host)) {
        throw new CustomDomainConflictError(CUSTOM_DOMAIN_CONFLICTS.HOST_TAKEN)
      }
      if (all.length >= limit) {
        throw new CustomDomainConflictError(CUSTOM_DOMAIN_CONFLICTS.DOMAIN_LIMIT_REACHED)
      }
      const now = clock()
      const record = {
        id: randomUUID(),
        host,
        state: 'pending',
        challengeHash,
        challengeExpiresAt,
        lastCheckedAt: null,
        verifiedAt: null,
        lastFailureReason: null,
        createdAt: now,
        updatedAt: now
      }
      records.set(record.id, record)
      return { ...record }
    },
    async findById(id) {
      const record = records.get(id)
      return record ? { ...record } : null
    },
    async list() {
      return [...records.values()].map((record) => ({ ...record }))
    },
    async recordChallengeCheck({ id, challengeHash, checkedAt, failureReason }) {
      const record = records.get(id)
      if (!record || record.state !== 'pending' || record.challengeHash !== challengeHash) {
        return null
      }
      return { ...touch(record, { lastCheckedAt: checkedAt, lastFailureReason: failureReason }) }
    },
    async rotateChallenge({ id, challengeHash, challengeExpiresAt }) {
      const record = records.get(id)
      if (!record || record.state === 'removed') return null
      return {
        ...touch(record, {
          state: 'pending',
          challengeHash,
          challengeExpiresAt,
          lastCheckedAt: null,
          verifiedAt: null,
          lastFailureReason: null
        })
      }
    },
    async verifyChallenge({ id, challengeHash, checkedAt }) {
      const record = records.get(id)
      if (
        !record ||
        record.state !== 'pending' ||
        record.challengeHash !== challengeHash ||
        record.challengeExpiresAt <= checkedAt
      ) {
        return null
      }
      return {
        ...touch(record, {
          state: 'verified',
          lastCheckedAt: checkedAt,
          verifiedAt: checkedAt,
          lastFailureReason: null
        })
      }
    },
    async transition({ id, state, lastCheckedAt, verifiedAt, lastFailureReason }) {
      const record = records.get(id)
      if (!record) return null
      return {
        ...touch(record, {
          state,
          ...(lastCheckedAt === undefined ? {} : { lastCheckedAt }),
          ...(verifiedAt === undefined ? {} : { verifiedAt }),
          ...(lastFailureReason === undefined ? {} : { lastFailureReason })
        })
      }
    }
  })
}

/** In-memory fixed-window counter with the rate-limit repository's increment() shape. */
export function createInMemoryRateLimitCounter() {
  const windows = new Map()
  return {
    windows,
    async increment(key, timeWindow) {
      const window = windows.get(key) ?? { current: 0, ttl: timeWindow }
      window.current += 1
      windows.set(key, window)
      return { ...window }
    }
  }
}

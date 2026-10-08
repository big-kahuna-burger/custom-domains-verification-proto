import { and, asc, eq, ne, sql } from 'drizzle-orm'
import {
  CUSTOM_DOMAIN_CONFLICTS,
  CustomDomainConflictError,
  assertCustomDomainRepository
} from '@custom-domains/verification'

import database from './client.js'
import { customDomains } from './schema.js'

const UNIQUE_VIOLATION = '23505'
const CHECK_VIOLATION = '23514'

const CONFLICTS = new Map([
  [`${UNIQUE_VIOLATION}:CustomDomain_active_host_key`, CUSTOM_DOMAIN_CONFLICTS.HOST_TAKEN],
  [`${CHECK_VIOLATION}:CustomDomain_limit_check`, CUSTOM_DOMAIN_CONFLICTS.DOMAIN_LIMIT_REACHED]
])

// Translates the active-host index and the domain-limit trigger into the port's conflict error.
function conflictFrom(error) {
  for (let current = error; current; current = current.cause) {
    const code = CONFLICTS.get(`${current.code}:${current.constraint}`)
    if (code) return new CustomDomainConflictError(code, { cause: error })
  }
  return error
}

/**
 * PostgreSQL implementation of the management custom-domain repository port.
 * @param {typeof database} [db]
 */
export function createCustomDomainRepository(db = database) {
  if (!db) throw new Error('PostgreSQL is required for custom domains')

  return assertCustomDomainRepository({
    async create({ host, challengeHash, challengeExpiresAt }) {
      try {
        const [row] = await db
          .insert(customDomains)
          .values({ host, challengeHash, challengeExpiresAt })
          .returning()
        return row
      } catch (error) {
        throw conflictFrom(error)
      }
    },

    async findById(id) {
      const [row] = await db.select().from(customDomains).where(eq(customDomains.id, id)).limit(1)
      return row ?? null
    },

    list() {
      return db
        .select()
        .from(customDomains)
        .orderBy(asc(customDomains.createdAt), asc(customDomains.id))
    },

    async recordChallengeCheck({ id, challengeHash, checkedAt, failureReason }) {
      const [row] = await db
        .update(customDomains)
        .set({
          lastCheckedAt: checkedAt,
          lastFailureReason: failureReason,
          updatedAt: sql`clock_timestamp()`
        })
        .where(
          and(
            eq(customDomains.id, id),
            eq(customDomains.state, 'pending'),
            eq(customDomains.challengeHash, challengeHash)
          )
        )
        .returning()
      return row ?? null
    },

    async rotateChallenge({ id, challengeHash, challengeExpiresAt }) {
      const [row] = await db
        .update(customDomains)
        .set({
          state: 'pending',
          challengeHash,
          challengeExpiresAt,
          lastCheckedAt: null,
          verifiedAt: null,
          lastFailureReason: null,
          updatedAt: sql`clock_timestamp()`
        })
        .where(and(eq(customDomains.id, id), ne(customDomains.state, 'removed')))
        .returning()
      return row ?? null
    },

    async verifyChallenge({ id, challengeHash, checkedAt }) {
      return db.transaction(async (transaction) => {
        const challenge = and(
          eq(customDomains.id, id),
          eq(customDomains.state, 'pending'),
          eq(customDomains.challengeHash, challengeHash)
        )
        const [candidate] = await transaction
          .select({ id: customDomains.id })
          .from(customDomains)
          .where(challenge)
          .for('update')
          .limit(1)
        if (!candidate) return null

        const [row] = await transaction
          .update(customDomains)
          .set({
            state: 'verified',
            lastCheckedAt: checkedAt,
            verifiedAt: checkedAt,
            lastFailureReason: null,
            updatedAt: sql`clock_timestamp()`
          })
          .where(and(challenge, sql`${customDomains.challengeExpiresAt} > clock_timestamp()`))
          .returning()
        return row ?? null
      })
    },

    async transition({ id, state, lastCheckedAt, verifiedAt, lastFailureReason }) {
      const [row] = await db
        .update(customDomains)
        .set({
          state,
          ...(lastCheckedAt === undefined ? {} : { lastCheckedAt }),
          ...(verifiedAt === undefined ? {} : { verifiedAt }),
          ...(lastFailureReason === undefined ? {} : { lastFailureReason }),
          updatedAt: sql`clock_timestamp()`
        })
        .where(eq(customDomains.id, id))
        .returning()
      return row ?? null
    }
  })
}

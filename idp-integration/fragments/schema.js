// Drizzle table and enum for custom domains, as they sat in the IdP's persistence/schema.js.
import { CUSTOM_DOMAIN_STATES } from '@custom-domains/verification'

export const customDomainState = pgEnum('CUSTOM_DOMAIN_STATE', CUSTOM_DOMAIN_STATES)

export const customDomains = pgTable(
  'CustomDomain',
  {
    id: uuid().primaryKey().defaultRandom(),
    host: text().notNull(),
    state: customDomainState().notNull().default('pending'),
    challengeHash: char({ length: 64 }).notNull(),
    challengeExpiresAt: timestamptz('challengeExpiresAt').notNull(),
    lastCheckedAt: timestamptz('lastCheckedAt'),
    verifiedAt: timestamptz('verifiedAt'),
    lastFailureReason: text(),
    createdAt: timestamptz('createdAt').notNull().defaultNow(),
    updatedAt: timestamptz('updatedAt').notNull().defaultNow()
  },
  (table) => [
    uniqueIndex('CustomDomain_active_host_key')
      .on(table.host)
      .where(sql`${table.state} <> 'removed'`),
    index('CustomDomain_created_idx').on(table.createdAt)
  ]
)

export const MANAGEMENT_API_PREFIX = '/manage/v1'

// Custom domains of this identity provider. Removed domains are never returned; they answer 404.
export const CUSTOM_DOMAIN_RESPONSE_STATES = Object.freeze([
  'pending',
  'verified',
  'active',
  'verification_lost',
  'failed'
])

// Stable machine-readable codes for custom-domain request failures that are not plain
// 401/403/404/503 management errors.
export const CUSTOM_DOMAIN_ERRORS = Object.freeze({
  invalidHost: Object.freeze({ statusCode: 400, error: 'Bad Request', code: 'invalid_host' }),
  hostTaken: Object.freeze({ statusCode: 409, error: 'Conflict', code: 'host_taken' }),
  domainLimitReached: Object.freeze({
    statusCode: 409,
    error: 'Conflict',
    code: 'domain_limit_reached'
  }),
  rateLimited: Object.freeze({ statusCode: 429, error: 'Too Many Requests', code: 'rate_limited' })
})

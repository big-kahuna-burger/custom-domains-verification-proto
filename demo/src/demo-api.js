import { MANAGEMENT_OPERATIONS } from '@custom-domains/contract'

const NOW = '2026-10-03T12:00:00.000Z'
const LATER = '2026-10-04T12:00:00.000Z'
const ID = '4a4d4ba1-3366-4f23-beb0-3cc41a58c001'

function domain(overrides = {}) {
  return {
    id: ID,
    host: 'xn--bcher-kva.example.com',
    displayHost: 'bücher.example.com',
    state: 'pending',
    challengeExpiresAt: LATER,
    lastCheckedAt: null,
    verifiedAt: null,
    lastFailureReason: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides
  }
}

const challenge = (item) => ({
  recordName: `_f0-challenge.${item.host}`,
  recordType: 'TXT',
  recordValue: `f0-domain-verification=${item.id.slice(0, 8)}-keep-this-value-secret`,
  expiresAt: item.challengeExpiresAt
})

export const DEMO_SCENARIOS = Object.freeze({
  setup: 'Setup in progress',
  recovery: 'Recovery needed',
  statuses: 'All statuses',
  empty: 'Empty',
  limit: 'At domain limit',
  error: 'Request error',
  loading: 'Loading'
})

function fixtures(scenario) {
  if (scenario === 'empty') return []
  if (scenario === 'limit') {
    return Array.from({ length: 10 }, (_, index) =>
      domain({
        id: `${String(index).padStart(8, '0')}-3366-4f23-beb0-3cc41a58c${String(index).padStart(3, '0')}`,
        host: `login-${index + 1}.example.com`,
        displayHost: `login-${index + 1}.example.com`,
        state: index % 2 === 0 ? 'verified' : 'active',
        verifiedAt: NOW
      })
    )
  }
  if (scenario === 'recovery') {
    return [
      domain({
        state: 'verification_lost',
        lastCheckedAt: NOW,
        verifiedAt: '2026-10-01T12:00:00.000Z',
        lastFailureReason: 'txt-record-mismatch'
      })
    ]
  }
  if (scenario === 'statuses') {
    return ['pending', 'verified', 'active', 'verification_lost', 'failed'].map((state, index) =>
      domain({
        id: `${String(index + 1).padStart(8, '0')}-3366-4f23-beb0-3cc41a58c${String(index + 1).padStart(3, '0')}`,
        host: `${state.replaceAll('_', '-')}.example.com`,
        displayHost: `${state.replaceAll('_', '-')}.example.com`,
        state,
        verifiedAt: ['verified', 'active', 'verification_lost'].includes(state) ? NOW : null,
        lastFailureReason:
          state === 'verification_lost'
            ? 'dns-nxdomain'
            : state === 'failed'
              ? 'dns-servfail'
              : null
      })
    )
  }
  return [domain()]
}

export function createDemoFetch(scenario = 'setup') {
  let domains = fixtures(scenario)
  const attempts = new Map()

  return async function demoFetch(input, options = {}) {
    if (scenario === 'loading') return new Promise(() => {})
    if (scenario === 'error') return response(503, { error: 'Service Unavailable' })

    await new Promise((resolve) => setTimeout(resolve, 180))
    const url = new URL(input)
    const path = url.pathname.replace('/manage/v1', '')
    const method = options.method ?? 'GET'

    if (method === MANAGEMENT_OPERATIONS.listCustomDomains.method && path === '/custom-domains') {
      return response(200, domains)
    }

    if (method === MANAGEMENT_OPERATIONS.createCustomDomain.method && path === '/custom-domains') {
      if (domains.length >= 10) {
        return response(409, { error: 'Conflict', code: 'domain_limit_reached' })
      }
      const { host } = JSON.parse(options.body)
      if (!host.includes('.') || host.includes('://')) {
        return response(400, { error: 'Bad Request', code: 'invalid_host', reason: 'hostname' })
      }
      if (domains.some((item) => item.host === host.toLowerCase())) {
        return response(409, { error: 'Conflict', code: 'host_taken' })
      }
      const item = domain({
        id: crypto.randomUUID(),
        host: host.toLowerCase(),
        displayHost: host.toLowerCase()
      })
      domains = [item, ...domains]
      return response(201, { domain: item, challenge: challenge(item) })
    }

    const id = path.split('/')[2]
    const item = domains.find((candidate) => candidate.id === id)
    if (!item) return response(404, { error: 'Not Found' })

    if (method === 'DELETE') {
      domains = domains.filter((candidate) => candidate.id !== id)
      return response(204)
    }

    if (path.endsWith('/challenge')) {
      const next = { ...item, state: 'pending', lastFailureReason: null, updatedAt: NOW }
      domains = domains.map((candidate) => (candidate.id === id ? next : candidate))
      return response(200, { domain: next, challenge: challenge(next) })
    }

    if (path.endsWith('/verification-checks')) {
      const count = attempts.get(id) ?? 0
      attempts.set(id, count + 1)
      if (count > 0) {
        return response(
          429,
          { error: 'Too Many Requests', code: 'rate_limited' },
          { 'retry-after': '60' }
        )
      }
      const verified = item.state === 'pending'
      const next = {
        ...item,
        state: verified ? 'verified' : item.state,
        lastCheckedAt: NOW,
        verifiedAt: verified ? NOW : item.verifiedAt,
        lastFailureReason: verified ? null : item.lastFailureReason,
        updatedAt: NOW
      }
      domains = domains.map((candidate) => (candidate.id === id ? next : candidate))
      return response(200, {
        verified,
        ...(verified ? {} : { reason: next.lastFailureReason ?? 'dns-nxdomain' }),
        retryable: !verified,
        domain: next
      })
    }

    return response(404, { error: 'Not Found' })
  }
}

function response(status, body, headers) {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers }
  })
}

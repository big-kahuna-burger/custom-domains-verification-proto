import { isIP } from 'node:net'
import { z } from 'zod'
import {
  DNS_LOOKUP_ERROR_CODES,
  DnsLookupError,
  assertLookupName,
  dnsBoundsSchema,
  joinTxtRecords,
  negativeCacheRetryAfterSeconds,
  traverseCname
} from './dns-lookup.js'
import { createDnsWireQuery } from './dns-wire-query.js'

const optionsSchema = dnsBoundsSchema.safeExtend({
  // Required on purpose: the host's resolv.conf is never used by accident.
  servers: z
    .array(z.string().refine((server) => isIP(server) !== 0, 'must be an IP address'))
    .min(1)
    .max(4),
  timeoutMillis: z.number().int().min(100).max(30000).default(3000),
  tries: z.number().int().min(1).max(3).default(2)
})

const responseSchema = z.object({
  rcode: z.string(),
  answers: z.array(z.unknown()),
  authorities: z.array(z.unknown())
})

const txtAnswerSchema = z.object({
  name: z.string(),
  type: z.literal('TXT'),
  class: z.literal('IN'),
  data: z.array(z.instanceof(Buffer))
})

const cnameAnswerSchema = z.object({
  name: z.string(),
  type: z.literal('CNAME'),
  class: z.literal('IN'),
  data: z.string()
})

const soaAuthoritySchema = z.object({
  type: z.literal('SOA'),
  class: z.literal('IN'),
  ttl: z.number().int().min(0).max(0xffffffff),
  data: z.object({ minimum: z.number().int().min(0).max(0xffffffff) })
})

const CODE_MAP = new Map([
  ['ETIMEOUT', DNS_LOOKUP_ERROR_CODES.TIMEOUT],
  ['EBADRESP', DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE]
])

const SERVFAIL_CODES = new Set(['ESERVFAIL', 'EREFUSED', 'ECONNREFUSED', 'ECONNRESET', 'ENOTIMP'])

function mapError(error) {
  if (error instanceof DnsLookupError) return error
  const code =
    CODE_MAP.get(error?.code) ??
    (SERVFAIL_CODES.has(error?.code) ? DNS_LOOKUP_ERROR_CODES.SERVFAIL : null)
  // Unknown errors are bugs, not DNS outcomes: surface them instead of labelling them retryable.
  if (!code) return error
  return new DnsLookupError(code, `DNS lookup failed: ${error.code}`, { cause: error })
}

function canonicalName(name) {
  const withoutTrailingDot = name.endsWith('.') ? name.slice(0, -1) : name
  return withoutTrailingDot.toLowerCase()
}

function negativeSoa(response) {
  const authority = response.authorities.find((record) => record?.type === 'SOA')
  const parsed = soaAuthoritySchema.safeParse(authority)
  if (!parsed.success) return undefined
  return { ttl: parsed.data.ttl, minimum: parsed.data.data.minimum }
}

function negativeError(code, response, bounds) {
  return new DnsLookupError(code, code === 'NXDOMAIN' ? 'Name does not exist' : 'No records', {
    retryAfterSeconds: negativeCacheRetryAfterSeconds(negativeSoa(response), bounds)
  })
}

function validateResponse(response, bounds) {
  const parsed = responseSchema.safeParse(response)
  if (!parsed.success) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Malformed DNS response', {
      cause: parsed.error
    })
  }
  if (parsed.data.rcode === 'NXDOMAIN') {
    throw negativeError(DNS_LOOKUP_ERROR_CODES.NXDOMAIN, parsed.data, bounds)
  }
  if (
    parsed.data.rcode === 'SERVFAIL' ||
    parsed.data.rcode === 'REFUSED' ||
    parsed.data.rcode === 'NOTIMP'
  ) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.SERVFAIL, `DNS ${parsed.data.rcode}`)
  }
  if (parsed.data.rcode !== 'NOERROR') {
    throw new DnsLookupError(
      DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE,
      `Unexpected DNS response code: ${parsed.data.rcode}`
    )
  }
  return parsed.data
}

function recordsAtOwner(response, host, type, schema) {
  const parsed = z
    .array(schema)
    .safeParse(response.answers.filter((record) => record?.type === type))
  if (!parsed.success) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, `Malformed ${type} answer`, {
      cause: parsed.error
    })
  }
  return parsed.data.filter((record) => canonicalName(record.name) === host)
}

/**
 * Production adapter over bounded DNS wire queries against explicitly configured recursive
 * resolvers. The decoded authority section supplies RFC 2308 negative-cache timing.
 */
export function createNodeDnsLookup(options, { queryDns } = {}) {
  const config = optionsSchema.parse(options)
  const bounds = {
    maxRecords: config.maxRecords,
    maxRecordLength: config.maxRecordLength,
    negativeCacheMinSeconds: config.negativeCacheMinSeconds,
    negativeCacheMaxSeconds: config.negativeCacheMaxSeconds,
    negativeCacheFallbackSeconds: config.negativeCacheFallbackSeconds
  }
  const queryWire = queryDns ?? createDnsWireQuery(config)

  async function query(host, type, schema) {
    assertLookupName(host)
    try {
      const response = validateResponse(await queryWire(host, type), bounds)
      const records = recordsAtOwner(response, host, type, schema)
      if (records.length === 0) throw negativeError(DNS_LOOKUP_ERROR_CODES.NODATA, response, bounds)
      return records
    } catch (error) {
      throw mapError(error)
    }
  }

  return {
    async lookupTxt(host) {
      const records = await query(host, 'TXT', txtAnswerSchema)
      return joinTxtRecords(
        records.map((record) => record.data.map((part) => part.toString('utf8'))),
        bounds
      )
    },
    async lookupCname(host) {
      return traverseCname(
        host,
        async (owner) => {
          const records = await query(owner, 'CNAME', cnameAnswerSchema)
          return records.map((record) => record.data)
        },
        bounds
      )
    }
  }
}

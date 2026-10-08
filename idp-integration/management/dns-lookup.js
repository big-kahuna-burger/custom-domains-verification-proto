import { z } from 'zod'
import { DNS_LOOKUP_ERROR_CODES, DnsLookupError } from '@custom-domains/verification'

export { DNS_LOOKUP_ERROR_CODES, DnsLookupError } from '@custom-domains/verification'

/**
 * DNS lookup port for custom domain verification.
 *
 * Consumers depend on this interface only:
 *   lookupTxt(host)   -> Promise<string[]>  one entry per TXT record, character-strings joined
 *   lookupCname(host) -> Promise<string[]>  full CNAME chain, excluding the queried owner
 * Failures are thrown as DnsLookupError with a stable code. NXDOMAIN and NODATA also expose an
 * integer `retryAfterSeconds` derived from RFC 2308 negative caching. The host must already be a
 * normalized ASCII name; the resolver target is server configuration and never comes from a
 * request.
 */

export const dnsBoundsSchema = z
  .object({
    maxRecords: z.number().int().min(1).max(64).default(16),
    // Measured in UTF-8 bytes of the joined record.
    maxRecordLength: z.number().int().min(1).max(65535).default(2048),
    negativeCacheMinSeconds: z.number().int().min(0).max(0xffffffff).default(0),
    negativeCacheMaxSeconds: z.number().int().min(0).max(0xffffffff).default(3600),
    negativeCacheFallbackSeconds: z.number().int().min(0).max(0xffffffff).default(60)
  })
  .refine((bounds) => bounds.negativeCacheMinSeconds <= bounds.negativeCacheMaxSeconds, {
    message: 'negativeCacheMinSeconds must not exceed negativeCacheMaxSeconds'
  })

const DEFAULT_DNS_BOUNDS = Object.freeze(dnsBoundsSchema.parse({}))
const MAX_CNAME_HOPS = 8

const negativeSoaSchema = z.object({
  ttl: z.number().int().min(0).max(0xffffffff),
  minimum: z.number().int().min(0).max(0xffffffff)
})

/** Derives the effective scheduler delay from the negative response's authority SOA. */
export function negativeCacheRetryAfterSeconds(soa, bounds = DEFAULT_DNS_BOUNDS) {
  const parsed = negativeSoaSchema.safeParse(soa)
  const seconds = parsed.success
    ? Math.min(parsed.data.ttl, parsed.data.minimum)
    : bounds.negativeCacheFallbackSeconds
  return Math.min(bounds.negativeCacheMaxSeconds, Math.max(bounds.negativeCacheMinSeconds, seconds))
}

function negativeError(code, message, soa, bounds) {
  return new DnsLookupError(code, message, {
    retryAfterSeconds: negativeCacheRetryAfterSeconds(soa, bounds)
  })
}

const MAX_NAME_LENGTH = 253
const MAX_LABEL_LENGTH = 63
const NAME_CHARACTERS = new Set('abcdefghijklmnopqrstuvwxyz0123456789-_'.split(''))

/**
 * Accepts only a lowercase ASCII, dot-separated name without a trailing dot. Normalization
 * (case, IDNA, trailing dot) belongs to the caller; this only guards the lookup boundary.
 */
export function assertLookupName(host) {
  const invalid = () => new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_NAME, 'Invalid DNS name')
  if (typeof host !== 'string' || host.length === 0 || host.length > MAX_NAME_LENGTH) {
    throw invalid()
  }
  for (const label of host.split('.')) {
    if (label.length === 0 || label.length > MAX_LABEL_LENGTH) throw invalid()
    if (label.startsWith('-') || label.endsWith('-')) throw invalid()
    for (const character of label) {
      if (!NAME_CHARACTERS.has(character)) throw invalid()
    }
  }
  return host
}

/**
 * Joins the character-strings of each TXT record without separators (RFC 1035 3.3.14) and
 * enforces the answer bounds. An oversized answer is rejected, never truncated, so a token
 * cannot be silently dropped.
 */
export function joinTxtRecords(records, bounds = DEFAULT_DNS_BOUNDS) {
  const malformed = () =>
    new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Malformed TXT answer')
  if (!Array.isArray(records)) throw malformed()
  if (records.length === 0) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.NODATA, 'No TXT records')
  }
  const joined = records.map((record) => {
    const strings = typeof record === 'string' ? [record] : record
    if (!Array.isArray(strings) || strings.some((part) => typeof part !== 'string')) {
      throw malformed()
    }
    return strings.join('')
  })
  return boundAnswer(joined, bounds)
}

function boundCnameTargets(targets, bounds = DEFAULT_DNS_BOUNDS) {
  if (!Array.isArray(targets) || targets.some((target) => typeof target !== 'string')) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Malformed CNAME answer')
  }
  if (targets.length === 0) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.NODATA, 'No CNAME records')
  }
  return boundAnswer(targets, bounds)
}

function canonicalizeCnameTarget(target, bounds) {
  const [bounded] = boundCnameTargets([target], bounds)
  const withoutTrailingDot = bounded.endsWith('.') ? bounded.slice(0, -1) : bounded
  const canonical = withoutTrailingDot.toLowerCase()
  try {
    return assertLookupName(canonical)
  } catch (error) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Malformed CNAME target', {
      cause: error
    })
  }
}

/**
 * Follows one CNAME answer per owner and returns every canonical target in traversal order.
 * NODATA terminates a non-empty chain. A target beyond hop eight or a repeated name is rejected
 * with a stable, non-retryable error.
 */
export async function traverseCname(host, lookupDirect, bounds = DEFAULT_DNS_BOUNDS) {
  assertLookupName(host)
  const chain = []
  const visited = new Set([host])
  let owner = host

  while (true) {
    let targets
    try {
      targets = boundCnameTargets(await lookupDirect(owner), bounds)
    } catch (error) {
      if (
        chain.length > 0 &&
        error instanceof DnsLookupError &&
        error.code === DNS_LOOKUP_ERROR_CODES.NODATA
      ) {
        return chain
      }
      throw error
    }

    if (targets.length !== 1) {
      throw new DnsLookupError(
        DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE,
        'A CNAME owner must have exactly one target'
      )
    }
    if (chain.length === MAX_CNAME_HOPS) {
      throw new DnsLookupError(
        DNS_LOOKUP_ERROR_CODES.CNAME_DEPTH_EXCEEDED,
        `CNAME chain exceeds ${MAX_CNAME_HOPS} hops`
      )
    }

    const target = canonicalizeCnameTarget(targets[0], bounds)
    if (visited.has(target)) {
      throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.CNAME_LOOP, 'CNAME chain contains a loop')
    }

    chain.push(target)
    visited.add(target)
    owner = target
  }
}

function boundAnswer(values, bounds) {
  if (values.length > bounds.maxRecords) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Too many records')
  }
  if (values.some((value) => Buffer.byteLength(value) > bounds.maxRecordLength)) {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.INVALID_RESPONSE, 'Record too long')
  }
  return values
}

/**
 * In-memory fake for tests; performs no I/O. `zone` maps a host to
 * `{ txt?, cname?, error?, soa?: { ttl, minimum } }`.
 * A host missing from the zone is NXDOMAIN; a host without the requested type is NODATA.
 */
export function createInMemoryDnsLookup({ zone = {}, bounds } = {}) {
  const parsedBounds = dnsBoundsSchema.parse(bounds ?? {})
  const entryFor = (host) => {
    assertLookupName(host)
    const entry = Object.hasOwn(zone, host) ? zone[host] : undefined
    if (entry === undefined)
      throw negativeError(
        DNS_LOOKUP_ERROR_CODES.NXDOMAIN,
        'Name does not exist',
        null,
        parsedBounds
      )
    if (
      entry.error === DNS_LOOKUP_ERROR_CODES.NXDOMAIN ||
      entry.error === DNS_LOOKUP_ERROR_CODES.NODATA
    ) {
      throw negativeError(entry.error, undefined, entry.soa, parsedBounds)
    }
    if (entry.error) throw new DnsLookupError(entry.error)
    return entry
  }
  return {
    async lookupTxt(host) {
      const entry = entryFor(host)
      if (!entry.txt?.length) {
        throw negativeError(
          DNS_LOOKUP_ERROR_CODES.NODATA,
          'No TXT records',
          entry.soa,
          parsedBounds
        )
      }
      return joinTxtRecords(entry.txt, parsedBounds)
    },
    async lookupCname(host) {
      return traverseCname(
        host,
        async (owner) => {
          const entry = entryFor(owner)
          if (!entry.cname?.length) {
            throw negativeError(
              DNS_LOOKUP_ERROR_CODES.NODATA,
              'No CNAME records',
              entry.soa,
              parsedBounds
            )
          }
          return entry.cname
        },
        parsedBounds
      )
    }
  }
}

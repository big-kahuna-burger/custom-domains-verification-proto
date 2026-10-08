/**
 * Stable failures returned by the injected DNS lookup port. DNS implementations remain with the
 * consuming application; the lifecycle depends only on lookupTxt(), lookupCname(), and this error.
 */
export const DNS_LOOKUP_ERROR_CODES = Object.freeze({
  NXDOMAIN: 'NXDOMAIN',
  NODATA: 'NODATA',
  SERVFAIL: 'SERVFAIL',
  TIMEOUT: 'TIMEOUT',
  INVALID_NAME: 'INVALID_NAME',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  CNAME_LOOP: 'CNAME_LOOP',
  CNAME_DEPTH_EXCEEDED: 'CNAME_DEPTH_EXCEEDED'
})

const RETRYABLE = new Set([DNS_LOOKUP_ERROR_CODES.SERVFAIL, DNS_LOOKUP_ERROR_CODES.TIMEOUT])

export class DnsLookupError extends Error {
  constructor(code, message, { retryAfterSeconds, ...options } = {}) {
    if (!Object.hasOwn(DNS_LOOKUP_ERROR_CODES, code)) {
      throw new TypeError(`Unknown DNS lookup error code: ${String(code)}`)
    }
    super(message ?? code, options)
    this.name = 'DnsLookupError'
    this.code = code
    this.retryable = RETRYABLE.has(code)
    // NXDOMAIN and NODATA carry the RFC 2308 negative-cache delay in whole seconds.
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds
  }
}

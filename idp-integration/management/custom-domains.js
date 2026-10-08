import {
  DNS_LOOKUP_ERROR_CODES,
  DnsLookupError,
  createCustomDomainVerification
} from '@custom-domains/verification'
import { customDomainDisplayHost, normalizeCustomDomainName } from './custom-domain-name.js'
import { createNodeDnsLookup } from './node-dns-lookup.js'

// Stands in for the DNS port when no resolvers are configured. Routes check `checksAvailable`
// first and answer 503, so this only guards against a missed check.
const unavailableDnsLookup = Object.freeze({
  async lookupTxt() {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.SERVFAIL, 'DNS resolvers are not configured')
  },
  async lookupCname() {
    throw new DnsLookupError(DNS_LOOKUP_ERROR_CODES.SERVFAIL, 'DNS resolvers are not configured')
  }
})

/**
 * Everything the custom-domain management routes need, built once by application assembly.
 * @param {{
 *   repository: object,
 *   identityProviderHost: string,
 *   dnsServers?: string[],
 *   dnsLookup?: { lookupTxt: Function, lookupCname: Function },
 *   now?: () => Date
 * }} options
 */
export function createCustomDomainManagement({
  repository,
  identityProviderHost,
  dnsServers,
  dnsLookup = dnsServers ? createNodeDnsLookup({ servers: dnsServers }) : undefined,
  now
}) {
  if (typeof identityProviderHost !== 'string' || identityProviderHost === '') {
    throw new TypeError('custom domain management requires the identity provider host')
  }
  const verification = createCustomDomainVerification({
    repository,
    dnsLookup: dnsLookup ?? unavailableDnsLookup,
    ...(now ? { now } : {})
  })

  return Object.freeze({
    repository,
    verification,
    checksAvailable: dnsLookup !== undefined,
    normalizeHost: (input) => normalizeCustomDomainName(input, identityProviderHost),
    displayHost: customDomainDisplayHost
  })
}
